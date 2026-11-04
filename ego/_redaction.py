"""Rédaction commune aux rapports texte et HTML : formats, plafonds, répliques.

Module privé : les rapports l'importent, l'API publique reste ego.rapport.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from string import Template

from ego.detection import Alerte
from ego.lecture import MARQUE_TRONCATURE, LigneRejetee
from ego.neutralisation import neutraliser

UNITES = (("jour", 86_400), ("heure", 3_600), ("minute", 60), ("seconde", 1))
MOINS_D_UNE_SECONDE = "moins d'une seconde"
COMPTE_SANS_NOM = "(sans nom)"
SEPARATEUR_COMPTES = ", "
# Un export hostile ne doit pas pouvoir noyer le rapport sous ses noms tentés,
# ni inonder le terminal de lignes rejetées.
LONGUEUR_MAX_COMPTE = 64
COMPTES_MAX_AFFICHES = 10
REJETS_MAX_AFFICHES = 20
# Rapport HTML : chaque bloc d'alerte pèse au plus ~13 Kio (voir test_rapport_html).
ALERTES_MAX_AFFICHEES = 200


def formater_duree(duree: timedelta) -> str:
    """Durée en français lisible : "4 minutes 12 secondes".

    Les fractions de seconde sont tronquées. Lève ValueError si duree < 0.
    """
    if duree < timedelta(0):
        raise ValueError(f"durée négative : {duree}")
    reste = duree // timedelta(seconds=1)
    if reste == 0:
        return MOINS_D_UNE_SECONDE
    parties = []
    for unite, secondes in UNITES:
        quantite, reste = divmod(reste, secondes)
        if quantite:
            pluriel = "s" if quantite > 1 else ""
            parties.append(f"{quantite} {unite}{pluriel}")
    return " ".join(parties)


def formater_instant(instant: datetime) -> str:
    """Heure d'origine et son décalage : "2026-11-03 02:14:05 UTC+01:00".

    Sans strftime, dont le rendu de %Y avant l'an 1000 dépend de la plateforme.
    """
    i = instant
    return (
        f"{i.year:04d}-{i.month:02d}-{i.day:02d} "
        f"{i.hour:02d}:{i.minute:02d}:{i.second:02d} {_fuseau(i)}"
    )


def _fuseau(instant: datetime) -> str:
    decalage = instant.utcoffset() or timedelta(0)
    minutes = decalage // timedelta(minutes=1)
    if minutes == 0:
        return "UTC"
    signe = "+" if minutes > 0 else "-"
    heures, minutes = divmod(abs(minutes), 60)
    return f"UTC{signe}{heures:02d}:{minutes:02d}"


def graine(alertes: Sequence[Alerte], rejets: Sequence[LigneRejetee]) -> int:
    """Graine du choix des variantes.

    Elle dépend des données, pour que le ton change d'un export à l'autre :
    mêmes données, même rapport.
    """
    return sum(a.total for a in alertes) + len(rejets)


def valeurs_alerte(alerte: Alerte) -> dict[str, str]:
    """Champs d'une alerte pour les répliques, IP et comptes déjà neutralisés.

    str(ip) peut porter un identifiant de zone arbitraire (fe80::1%<zone>) :
    neutralisé ici, une fois pour toutes, comme les comptes.
    """
    return {
        "ip": neutraliser(str(alerte.ip)),
        "nombre": str(alerte.pic),
        "duree": formater_duree(alerte.fin_pic - alerte.debut_pic),
        "comptes": formater_comptes(alerte.comptes),
        "total": str(alerte.total),
        "debut": formater_instant(alerte.debut_pic),
        "fin": formater_instant(alerte.fin_pic),
    }


def formater_comptes(comptes: tuple[str, ...]) -> str:
    affiches = SEPARATEUR_COMPTES.join(
        formater_compte(compte) for compte in comptes[:COMPTES_MAX_AFFICHES]
    )
    autres = len(comptes) - COMPTES_MAX_AFFICHES
    if autres <= 0:
        return affiches
    return f"{affiches} et {autres} autre{'s' if autres > 1 else ''}"


def formater_compte(compte: str) -> str:
    """Nom tenté par l'attaquant : tronqué, puis neutralisé, puis "(sans nom)".

    Tronquer d'abord : couper après neutralisation pourrait scinder un
    échappement (« \\x1b »). La marque de troncature est ajoutée après coup.
    Neutralisé ici une fois pour toutes : neutraliser() n'est pas idempotent.
    """
    if len(compte) <= LONGUEUR_MAX_COMPTE:
        return neutraliser(compte) or COMPTE_SANS_NOM
    garde = LONGUEUR_MAX_COMPTE - len(MARQUE_TRONCATURE)
    return neutraliser(compte[:garde]) + MARQUE_TRONCATURE


def remplir(variantes: tuple[str, ...], rang: int, valeurs: Mapping[str, str]) -> str:
    """Variante choisie par le rang, champs substitués."""
    # substitute strict : les champs ont été validés au chargement des modèles.
    return Template(variantes[rang % len(variantes)]).substitute(valeurs)
