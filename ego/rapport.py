"""Rapport d'Ego : texte rédigé à partir des alertes et des modèles."""

from collections.abc import Mapping, Sequence
from datetime import timedelta

from ego._redaction import (
    formater_duree,
    formater_instant,
    graine as calculer_graine,
    remplir,
    valeurs_alerte,
)
from ego.detection import Alerte
from ego.lecture import LigneRejetee
from ego.modeles import Modeles

# API publique du module : formater_duree et formater_instant sont réexportés.
__all__ = ["formater_duree", "formater_instant", "rediger"]


def rediger(
    alertes: Sequence[Alerte],
    rejets: Sequence[LigneRejetee],
    seuil: int,
    fenetre: timedelta,
    modeles: Modeles,
) -> str:
    """Texte du rapport. Fonction pure : aucune lecture, aucune écriture.

    Choix des variantes déterministe : mêmes données, même rapport. La graine
    dépend des données, pour que le ton change d'un export à l'autre ; dans une
    section, les variantes tournent d'une alerte à la suivante.
    """
    graine = calculer_graine(alertes, rejets)
    communs = {"seuil": str(seuil), "fenetre": formater_duree(fenetre)}
    externes = [a for a in alertes if not a.est_locale]
    locales = [a for a in alertes if a.est_locale]
    blocs = [
        remplir(modeles.entete, graine, communs),
        "" if alertes else remplir(modeles.rien_a_signaler, graine, communs),
        _section(externes, modeles.alerte, graine, communs),
        _section(locales, modeles.alerte_locale, graine, communs),
        _lignes_rejetees(rejets, modeles, graine, communs),
        remplir(modeles.conclusion, graine, communs),
    ]
    return "\n\n".join(bloc for bloc in blocs if bloc) + "\n"


def _section(
    alertes: Sequence[Alerte],
    variantes: tuple[str, ...],
    graine: int,
    communs: Mapping[str, str],
) -> str:
    return "\n".join(
        remplir(variantes, graine + rang, {**communs, **valeurs_alerte(alerte)})
        for rang, alerte in enumerate(alertes)
    )


def _lignes_rejetees(
    rejets: Sequence[LigneRejetee],
    modeles: Modeles,
    graine: int,
    communs: Mapping[str, str],
) -> str:
    if not rejets:
        return ""
    valeurs = {**communs, "nombre": str(len(rejets))}
    return remplir(modeles.lignes_rejetees, graine, valeurs)
