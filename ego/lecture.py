"""Lecture des exports CSV produits par export-4625.ps1.

Format attendu : UTF-8 (BOM facultatif), séparateur virgule, en-tête contenant
au moins les colonnes Date, Compte et IP (lues par nom, dans n'importe quel ordre).

Une ligne inexploitable ne fait jamais échouer la lecture : elle devient une
LigneRejetee. Seul un en-tête absent ou incomplet lève ErreurFormat, car rien
n'est alors interprétable. Les lignes entièrement vides sont ignorées sans être
comptées comme rejetées.
"""

import csv
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Protocol, TextIO

AdresseIP = IPv4Address | IPv6Address

# Libellé de l'origine sans adresse : écrit par le programme, jamais lu dans l'export.
LIBELLE_SANS_IP = "(local, sans IP)"


@dataclass(frozen=True)
class SansIP:
    """Origine des échecs que Windows enregistre sans adresse (IpAddress « - »).

    Écran de connexion ou de déverrouillage, services et autres ouvertures
    locales, selon les cas. Sans champ : toutes les instances sont égales, et
    tous les « - » d'un export forment une seule origine.
    """

    def __str__(self) -> str:
        return LIBELLE_SANS_IP


SANS_IP = SansIP()
# Origine d'un échec : une adresse IP, ou SANS_IP. Seuls est_locale() et le tri des
# alertes appellent des méthodes d'adresse ; ailleurs, str() et isinstance(SansIP).
Origine = AdresseIP | SansIP
VALEUR_SANS_IP = "-"


def est_locale(origine: Origine) -> bool:
    """Vrai pour SANS_IP et pour une adresse de bouclage (::1, 127.0.0.0/8)."""
    return isinstance(origine, SansIP) or origine.is_loopback


COLONNE_DATE = "Date"
COLONNE_COMPTE = "Compte"
COLONNE_IP = "IP"
COLONNES_REQUISES = (COLONNE_DATE, COLONNE_COMPTE, COLONNE_IP)
VALEUR_IP_ABSENTE = ""

# Format "o" de PowerShell : 2026-11-03T08:12:45.1234567+01:00 (ou suffixe Z).
# Vérifié avant fromisoformat, dont la tolérance varie selon la version de Python.
# Le décalage est facultatif ici pour distinguer « sans fuseau » de « illisible ».
FORMAT_DATE_O = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
    r"T(?:[01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,7})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})?"
)

# Longueur maximale de LigneRejetee.detail : un fichier hostile ne doit pas
# pouvoir faire conserver des mégaoctets de valeurs fautives.
LONGUEUR_MAX_DETAIL = 100
MARQUE_TRONCATURE = "…"

# Marge dans laquelle tout horodatage accepté reste calculable (conversion UTC,
# ajout ou retrait d'une durée, en UTC comme dans son fuseau d'origine). Les
# fenêtres de détection ne doivent pas la dépasser.
MARGE_CALCUL = timedelta(days=1)


class ErreurFormat(Exception):
    """L'en-tête attendu est absent : aucune ligne ne peut être interprétée."""


class Raison(Enum):
    """Motif de rejet d'une ligne ; la valeur est un libellé technique lisible."""

    CSV_ILLISIBLE = "ligne CSV illisible"
    COLONNES = "nombre de champs incorrect"
    DATE_ILLISIBLE = "date illisible"
    DATE_SANS_FUSEAU = "date sans fuseau horaire"
    IP_ABSENTE = "IP absente"
    IP_INVALIDE = "IP invalide"


@dataclass(frozen=True)
class Evenement:
    """Un échec d'ouverture de session exploitable."""

    horodatage: datetime  # toujours avec fuseau horaire
    # Peut être vide. Contrôlé par l'attaquant (nom tenté) : comme
    # LigneRejetee.detail, à assainir avant tout affichage.
    compte: str
    ip: Origine  # adresse IP, ou SANS_IP pour « - »

    @property
    def est_locale(self) -> bool:
        """Vrai pour SANS_IP et pour une adresse de bouclage (::1, 127.0.0.0/8)."""
        return est_locale(self.ip)


@dataclass(frozen=True)
class LigneRejetee:
    """Une ligne écartée.

    `detail` reprend la valeur brute fautive, bornée à LONGUEUR_MAX_DETAIL
    caractères : à assainir avant tout affichage.
    """

    numero: int  # ligne physique dans le fichier ; l'en-tête est la ligne 1
    raison: Raison
    detail: str


@dataclass(frozen=True)
class ResultatLecture:
    evenements: tuple[Evenement, ...]
    rejets: tuple[LigneRejetee, ...]


class _LecteurCsv(Protocol):
    """Ce qu'on utilise d'un objet renvoyé par csv.reader."""

    line_num: int

    def __next__(self) -> list[str]: ...


@dataclass(frozen=True)
class _Colonnes:
    date: int
    compte: int
    ip: int
    largeur: int


def lire_export(chemin: Path) -> ResultatLecture:
    """Lit un export sur disque. Les erreurs d'accès (OSError) sont propagées."""
    with open(chemin, encoding="utf-8-sig", errors="replace", newline="") as flux:
        return analyser_csv(flux)


def analyser_csv(flux: TextIO) -> ResultatLecture:
    """Analyse un flux CSV texte ; lève ErreurFormat si l'en-tête est inutilisable."""
    lecteur = csv.reader(flux)
    colonnes = _lire_en_tete(lecteur)
    resultats = [
        _analyser_ligne(numero, champs, colonnes)
        for numero, champs in _parcourir(lecteur)
    ]
    return ResultatLecture(
        evenements=tuple(r for r in resultats if isinstance(r, Evenement)),
        rejets=tuple(r for r in resultats if isinstance(r, LigneRejetee)),
    )


def _lire_en_tete(lecteur: _LecteurCsv) -> _Colonnes:
    attendu = ",".join(COLONNES_REQUISES)
    try:
        noms = [nom.strip() for nom in next(lecteur)]
    except StopIteration:
        raise ErreurFormat(f"fichier vide : en-tête {attendu} attendu") from None
    except csv.Error as erreur:
        raise ErreurFormat(
            f"en-tête illisible ({erreur}) : {attendu} attendu"
        ) from None
    manquantes = [nom for nom in COLONNES_REQUISES if nom not in noms]
    if manquantes:
        raise ErreurFormat(
            f"colonne(s) absente(s) de l'en-tête : {', '.join(manquantes)} "
            f"(attendu : {attendu})"
        )
    return _Colonnes(
        date=noms.index(COLONNE_DATE),
        compte=noms.index(COLONNE_COMPTE),
        ip=noms.index(COLONNE_IP),
        largeur=len(noms),
    )


def _parcourir(lecteur: _LecteurCsv) -> Iterator[tuple[int, list[str] | csv.Error]]:
    """Produit (numéro de la première ligne de l'enregistrement, champs).

    line_num vaut la dernière ligne lue : un champ entre guillemets peut couvrir
    plusieurs lignes, on note donc le début avant de lire.
    Une erreur CSV prend la place des champs sans interrompre la lecture.
    """
    while True:
        debut = lecteur.line_num + 1
        try:
            champs = next(lecteur)
        except StopIteration:
            return
        except csv.Error as erreur:
            yield debut, erreur
            continue
        if champs:
            yield debut, champs


def _analyser_ligne(
    numero: int, champs: list[str] | csv.Error, colonnes: _Colonnes
) -> Evenement | LigneRejetee:
    if isinstance(champs, csv.Error):
        return _rejet(numero, Raison.CSV_ILLISIBLE, str(champs))
    if len(champs) != colonnes.largeur:
        detail = f"{len(champs)} champs au lieu de {colonnes.largeur}"
        return _rejet(numero, Raison.COLONNES, detail)

    texte_date = champs[colonnes.date].strip()
    horodatage = _lire_date(texte_date)
    if isinstance(horodatage, Raison):
        return _rejet(numero, horodatage, texte_date)

    texte_ip = champs[colonnes.ip].strip()
    ip = _lire_ip(texte_ip)
    if isinstance(ip, Raison):
        return _rejet(numero, ip, texte_ip)

    compte = champs[colonnes.compte].strip()
    return Evenement(horodatage=horodatage, compte=compte, ip=ip)


def _rejet(numero: int, raison: Raison, detail: str) -> LigneRejetee:
    if len(detail) > LONGUEUR_MAX_DETAIL:
        garde = LONGUEUR_MAX_DETAIL - len(MARQUE_TRONCATURE)
        detail = detail[:garde] + MARQUE_TRONCATURE
    return LigneRejetee(numero, raison, detail)


def _lire_date(texte: str) -> datetime | Raison:
    if FORMAT_DATE_O.fullmatch(texte) is None:
        return Raison.DATE_ILLISIBLE
    try:
        horodatage = datetime.fromisoformat(texte)
    except ValueError:
        return Raison.DATE_ILLISIBLE
    if horodatage.utcoffset() is None:
        return Raison.DATE_SANS_FUSEAU
    if not _est_calculable(horodatage):
        return Raison.DATE_ILLISIBLE
    return horodatage


def _est_calculable(horodatage: datetime) -> bool:
    """Faux aux bords du calendrier, où un calcul lèverait OverflowError.

    La marge doit tenir en UTC et dans le fuseau d'origine : avec un décalage
    de ±14 h, l'un peut déborder sans l'autre.
    """
    try:
        for instant in (horodatage, horodatage.astimezone(timezone.utc)):
            instant - MARGE_CALCUL
            instant + MARGE_CALCUL
    except OverflowError:
        return False
    return True


def _lire_ip(texte: str) -> Origine | Raison:
    # texte est déjà débarrassé de ses espaces : « - » entouré d'espaces compte.
    # Seul le trait d'union ASCII exact : « – », « -- » ou « N/A » restent invalides.
    if texte == VALEUR_SANS_IP:
        return SANS_IP
    if texte == VALEUR_IP_ABSENTE:
        return Raison.IP_ABSENTE
    try:
        ip = ip_address(texte)
    except ValueError:
        return Raison.IP_INVALIDE
    # Identifiant de zone (fe80::1%12) : jamais produit par un 4625, et le même
    # préfixe sur deux interfaces peut désigner deux machines. Refusé.
    if isinstance(ip, IPv6Address) and ip.scope_id is not None:
        return Raison.IP_INVALIDE
    # Une IPv4 mappée (::ffff:a.b.c.d) est la même source que a.b.c.d.
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip
