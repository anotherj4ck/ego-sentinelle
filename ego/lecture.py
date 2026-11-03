"""Lecture des exports CSV produits par export-4625.ps1.

Format attendu : UTF-8 (BOM facultatif), séparateur virgule, en-tête contenant
au moins les colonnes Date, Compte et IP (lues par nom, dans n'importe quel ordre).

Une ligne inexploitable ne fait jamais échouer la lecture : elle devient une
LigneRejetee. Seul un en-tête absent ou incomplet lève ErreurFormat, car rien
n'est alors interprétable. Les lignes entièrement vides sont ignorées sans être
comptées comme rejetées.
"""

import csv
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Protocol, TextIO

AdresseIP = IPv4Address | IPv6Address

COLONNE_DATE = "Date"
COLONNE_COMPTE = "Compte"
COLONNE_IP = "IP"
COLONNES_REQUISES = (COLONNE_DATE, COLONNE_COMPTE, COLONNE_IP)
VALEURS_IP_ABSENTE = frozenset({"", "-"})


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
    compte: str  # peut être vide
    ip: AdresseIP

    @property
    def est_locale(self) -> bool:
        """Vrai pour une adresse de bouclage (::1, 127.0.0.0/8)."""
        return self.ip.is_loopback


@dataclass(frozen=True)
class LigneRejetee:
    """Une ligne écartée.

    `detail` reprend la valeur brute fautive : à assainir avant tout affichage.
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
    """Produit (numéro de ligne, champs).

    Une erreur CSV prend la place des champs sans interrompre la lecture.
    """
    while True:
        try:
            champs = next(lecteur)
        except StopIteration:
            return
        except csv.Error as erreur:
            yield lecteur.line_num, erreur
            continue
        if champs:
            yield lecteur.line_num, champs


def _analyser_ligne(
    numero: int, champs: list[str] | csv.Error, colonnes: _Colonnes
) -> Evenement | LigneRejetee:
    if isinstance(champs, csv.Error):
        return LigneRejetee(numero, Raison.CSV_ILLISIBLE, str(champs))
    if len(champs) != colonnes.largeur:
        detail = f"{len(champs)} champs au lieu de {colonnes.largeur}"
        return LigneRejetee(numero, Raison.COLONNES, detail)

    texte_date = champs[colonnes.date].strip()
    horodatage = _lire_date(texte_date)
    if isinstance(horodatage, Raison):
        return LigneRejetee(numero, horodatage, texte_date)

    texte_ip = champs[colonnes.ip].strip()
    ip = _lire_ip(texte_ip)
    if isinstance(ip, Raison):
        return LigneRejetee(numero, ip, texte_ip)

    compte = champs[colonnes.compte].strip()
    return Evenement(horodatage=horodatage, compte=compte, ip=ip)


def _lire_date(texte: str) -> datetime | Raison:
    try:
        horodatage = datetime.fromisoformat(texte)
    except ValueError:
        return Raison.DATE_ILLISIBLE
    if horodatage.utcoffset() is None:
        return Raison.DATE_SANS_FUSEAU
    return horodatage


def _lire_ip(texte: str) -> AdresseIP | Raison:
    if texte in VALEURS_IP_ABSENTE:
        return Raison.IP_ABSENTE
    try:
        ip = ip_address(texte)
    except ValueError:
        return Raison.IP_INVALIDE
    # Une IPv4 mappée (::ffff:a.b.c.d) est la même source que a.b.c.d.
    if isinstance(ip, IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip
