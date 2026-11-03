"""Modèles des répliques d'Ego : chargement et validation (modeles/ego.json)."""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from string import Template
from types import MappingProxyType

CHAMPS_ALERTE = frozenset(
    {"ip", "nombre", "duree", "comptes", "seuil", "fenetre", "total", "debut", "fin"}
)
CHAMPS_GLOBAUX = frozenset({"seuil", "fenetre"})

# Champs que chaque réplique peut utiliser : ceux dont le rapport dispose pour elle.
CHAMPS_PAR_CLE: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "entete": CHAMPS_GLOBAUX,
        "alerte": CHAMPS_ALERTE,
        "alerte_locale": CHAMPS_ALERTE,
        "rien_a_signaler": CHAMPS_GLOBAUX,
        "lignes_rejetees": CHAMPS_GLOBAUX | {"nombre"},  # nombre de lignes rejetées
        "conclusion": CHAMPS_GLOBAUX,
    }
)
CLES = tuple(CHAMPS_PAR_CLE)


class ErreurModeles(ValueError):
    """Fichier de modèles inutilisable."""


@dataclass(frozen=True)
class Modeles:
    """Variantes string.Template de chaque réplique."""

    entete: tuple[str, ...]
    alerte: tuple[str, ...]
    alerte_locale: tuple[str, ...]
    rien_a_signaler: tuple[str, ...]
    lignes_rejetees: tuple[str, ...]
    conclusion: tuple[str, ...]

    def __post_init__(self) -> None:
        for cle in CLES:
            _valider_variantes(cle, getattr(self, cle))


def charger_modeles(chemin: Path) -> Modeles:
    """Lit et valide le fichier de modèles. Lève ErreurModeles s'il est inutilisable.

    Un fichier absent ou illisible lève OSError, laissée à l'appelant.
    """
    # utf-8-sig : tolère le BOM qu'ajoutent certains éditeurs Windows.
    try:
        texte = chemin.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as erreur:
        raise ErreurModeles(f"encodage invalide : UTF-8 attendu ({erreur})") from erreur
    try:
        donnees = json.loads(texte, object_pairs_hook=_objet_sans_doublon)
    except json.JSONDecodeError as erreur:
        raise ErreurModeles(f"JSON invalide : {erreur}") from erreur
    if not isinstance(donnees, dict):
        raise ErreurModeles("objet JSON attendu à la racine")
    absentes = [cle for cle in CLES if cle not in donnees]
    if absentes:
        raise ErreurModeles(f"clé(s) absente(s) : {', '.join(absentes)}")
    inconnues = sorted(set(donnees) - set(CLES))
    if inconnues:
        raise ErreurModeles(f"clé(s) inconnue(s) : {', '.join(inconnues)}")
    return Modeles(**{cle: _en_tuple(cle, donnees[cle]) for cle in CLES})


def _en_tuple(cle: str, valeur: object) -> tuple[str, ...]:
    if not isinstance(valeur, list):
        raise ErreurModeles(f"{cle} : liste de variantes attendue")
    return tuple(valeur)


def _valider_variantes(cle: str, variantes: tuple[str, ...]) -> None:
    if not variantes:
        raise ErreurModeles(f"{cle} : au moins une variante attendue")
    for rang, variante in enumerate(variantes, start=1):
        if not isinstance(variante, str) or not variante.strip():
            raise ErreurModeles(f"{cle}, variante {rang} : texte non vide attendu")
        modele = Template(variante)
        if not modele.is_valid():
            raise ErreurModeles(
                f"{cle}, variante {rang} : modèle invalide"
                " ($ isolé ? écrire $$ pour un dollar)"
            )
        interdits = sorted(set(modele.get_identifiers()) - CHAMPS_PAR_CLE[cle])
        if interdits:
            raise ErreurModeles(
                f"{cle}, variante {rang} : champ(s) non autorisé(s) : "
                f"{_dollars(interdits)} (autorisés : "
                f"{_dollars(sorted(CHAMPS_PAR_CLE[cle]))})"
            )


def _dollars(champs: list[str]) -> str:
    return " ".join(f"${champ}" for champ in champs)


def _objet_sans_doublon(paires: list[tuple[str, object]]) -> dict[str, object]:
    objet: dict[str, object] = {}
    for cle, valeur in paires:
        if cle in objet:
            raise ErreurModeles(f"clé en double : {cle}")
        objet[cle] = valeur
    return objet
