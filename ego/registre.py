"""Registre d'Ego : tout ce qu'il a collecté dans les alertes, IP et comptes mêlés."""

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from ego.detection import Alerte

PLAFOND_REGISTRE = 50


@dataclass(frozen=True)
class Registre:
    """Noms bruts, à neutraliser au rendu comme dans le rapport texte."""

    noms: tuple[str, ...]  # au plus `plafond`, dans l'ordre d'apparition
    total: int  # entrées uniques, affichées ou non
    masques: int  # total - len(noms)


def collecter_registre(
    alertes: Iterable[Alerte], plafond: int = PLAFOND_REGISTRE
) -> Registre:
    """IP puis comptes de chaque alerte, sans doublon de casse.

    La première graphie rencontrée est gardée. Le plafond s'applique après le
    dédoublonnage. Lève ValueError si plafond n'est pas un entier >= 1.
    """
    # bool est un int en Python : True passerait pour 1.
    if isinstance(plafond, bool) or not isinstance(plafond, int) or plafond < 1:
        raise ValueError(f"plafond invalide : {plafond!r} (entier >= 1 attendu)")
    # Clé lower() -> première graphie. Pas casefold() : il confond « ß » et « ss »,
    # que Windows tient pour deux comptes distincts.
    uniques: dict[str, str] = {}
    for nom in _noms(alertes):
        uniques.setdefault(nom.lower(), nom)
    noms = tuple(uniques.values())[:plafond]
    return Registre(noms=noms, total=len(uniques), masques=len(uniques) - len(noms))


def _noms(alertes: Iterable[Alerte]) -> Iterator[str]:
    for alerte in alertes:
        yield str(alerte.ip)
        yield from alerte.comptes
