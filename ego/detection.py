"""Détection des IP à l'origine d'échecs répétés, par fenêtre glissante."""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from ego.lecture import MARGE_CALCUL, AdresseIP, Evenement

SEUIL_ECHECS = 5
FENETRE = timedelta(minutes=10)


@dataclass(frozen=True)
class Alerte:
    """Une IP ayant atteint le seuil d'échecs dans une fenêtre."""

    ip: AdresseIP
    pic: int  # plus grand nombre d'échecs dans une même fenêtre
    debut_pic: datetime  # premier échec de cette fenêtre
    fin_pic: datetime  # dernier échec de cette fenêtre
    total: int  # tous les échecs de cette IP dans l'export
    comptes: tuple[str, ...]  # comptes visés, distincts et triés

    @property
    def est_locale(self) -> bool:
        return self.ip.is_loopback


def detecter(
    evenements: Iterable[Evenement],
    seuil: int = SEUIL_ECHECS,
    fenetre: timedelta = FENETRE,
) -> tuple[Alerte, ...]:
    """Alertes des IP ayant au moins `seuil` échecs dans une même `fenetre`.

    Lève ValueError si seuil < 1 ou si la fenêtre n'est pas dans ]0, MARGE_CALCUL].
    """
    _valider_parametres(seuil, fenetre)
    alertes = []
    for ip, evenements_ip in _grouper_par_ip(evenements).items():
        horodatages = sorted(e.horodatage for e in evenements_ip)
        pic = _meilleure_fenetre(horodatages, fenetre)
        if pic.nombre >= seuil:
            alertes.append(
                Alerte(
                    ip=ip,
                    pic=pic.nombre,
                    debut_pic=horodatages[pic.debut],
                    fin_pic=horodatages[pic.fin],
                    total=len(horodatages),
                    comptes=tuple(sorted({e.compte for e in evenements_ip})),
                )
            )
    return tuple(sorted(alertes, key=_cle_de_tri))


def _valider_parametres(seuil: int, fenetre: timedelta) -> None:
    if seuil < 1:
        raise ValueError(f"seuil invalide : {seuil} (minimum 1)")
    # Au-delà de MARGE_CALCUL, les calculs sur les dates acceptées à la lecture
    # pourraient déborder (OverflowError).
    if not timedelta(0) < fenetre <= MARGE_CALCUL:
        raise ValueError(
            f"fenêtre invalide : {fenetre} (attendu : > 0 et <= {MARGE_CALCUL})"
        )


def _cle_de_tri(alerte: Alerte) -> tuple[int, int, AdresseIP]:
    # Pic décroissant, puis IP ; la version d'abord, car IPv4 et IPv6 ne se
    # comparent pas entre elles.
    return (-alerte.pic, alerte.ip.version, alerte.ip)


@dataclass(frozen=True)
class _Fenetre:
    nombre: int
    debut: int  # indice du premier échec de la fenêtre
    fin: int  # indice du dernier échec de la fenêtre


def _meilleure_fenetre(horodatages: list[datetime], fenetre: timedelta) -> _Fenetre:
    """Fenêtre glissante à deux pointeurs sur des horodatages triés.

    Borne incluse (dernier - premier <= fenetre) ; à égalité, la plus ancienne.
    """
    meilleure = _Fenetre(nombre=0, debut=0, fin=0)
    gauche = 0
    for droite, instant in enumerate(horodatages):
        while instant - horodatages[gauche] > fenetre:
            gauche += 1
        nombre = droite - gauche + 1
        if nombre > meilleure.nombre:
            meilleure = _Fenetre(nombre=nombre, debut=gauche, fin=droite)
    return meilleure


def _grouper_par_ip(
    evenements: Iterable[Evenement],
) -> dict[AdresseIP, list[Evenement]]:
    groupes: dict[AdresseIP, list[Evenement]] = {}
    for evenement in evenements:
        groupes.setdefault(evenement.ip, []).append(evenement)
    return groupes
