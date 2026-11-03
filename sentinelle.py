"""Ego Sentinelle : rapport d'Ego sur un export d'échecs de connexion 4625."""

import argparse
import io
import sys
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from ego.detection import FENETRE, SEUIL_ECHECS, detecter
from ego.lecture import (
    MARGE_CALCUL,
    ErreurFormat,
    LigneRejetee,
    ResultatLecture,
    lire_export,
)
from ego.modeles import ErreurModeles, Modeles, charger_modeles
from ego.neutralisation import neutraliser
from ego.rapport import rediger

# À côté du script, et non dans le dossier courant : sentinelle.py doit
# fonctionner lancé depuis n'importe où.
MODELES_PAR_DEFAUT = Path(__file__).resolve().parent / "modeles" / "ego.json"

CODE_AUCUNE_ALERTE = 0
CODE_ALERTES = 1
CODE_ERREUR = 2

# Un fichier hostile ne doit pas pouvoir inonder le terminal.
REJETS_MAX_AFFICHES = 20

UNE_MINUTE = timedelta(minutes=1)
# Au-delà, les calculs sur les dates acceptées à la lecture pourraient déborder.
FENETRE_MAX_MINUTES = MARGE_CALCUL // UNE_MINUTE


class _Echec(Exception):
    """Erreur signalée à l'utilisateur par un message, jamais par un traceback."""


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée. Codes : 0 aucune alerte, 1 alertes, 2 erreur."""
    _sorties_en_utf8()
    arguments = _analyseur().parse_args(argv)
    try:
        return _executer(arguments)
    except _Echec as echec:
        print(f"sentinelle.py : erreur : {echec}", file=sys.stderr)
        return CODE_ERREUR


def _sorties_en_utf8() -> None:
    # Vers un pipe ou une redirection, Python encode par défaut selon la
    # page de code Windows (cp1252) : « é » deviendrait 0xE9 et « ā » lèverait
    # UnicodeEncodeError. Le rapport et les messages sortent toujours en UTF-8.
    for flux in (sys.stdout, sys.stderr):
        if isinstance(flux, io.TextIOWrapper):
            flux.reconfigure(encoding="utf-8")


def _executer(arguments: argparse.Namespace) -> int:
    seuil = arguments.seuil
    fenetre = arguments.fenetre * UNE_MINUTE
    lecture = _lire_export(arguments.export)
    modeles = _charger_modeles(arguments.modeles)
    try:
        alertes = detecter(lecture.evenements, seuil, fenetre)
    except ValueError as erreur:
        raise _Echec(f"paramètres invalides : {erreur}") from erreur
    rapport = rediger(alertes, lecture.rejets, seuil, fenetre, modeles)
    _publier(rapport, arguments.sortie)
    for ligne in _lignes_de_rejets(lecture.rejets):
        print(ligne, file=sys.stderr)
    return CODE_ALERTES if alertes else CODE_AUCUNE_ALERTE


def _lire_export(chemin: Path) -> ResultatLecture:
    try:
        return lire_export(chemin)
    except FileNotFoundError as erreur:
        raise _Echec(f"export introuvable : {chemin}") from erreur
    except OSError as erreur:
        raise _Echec(f"export illisible : {chemin} ({erreur.strerror})") from erreur
    except ErreurFormat as erreur:
        raise _Echec(f"export invalide : {chemin} : {erreur}") from erreur


def _charger_modeles(chemin: Path) -> Modeles:
    try:
        return charger_modeles(chemin)
    except FileNotFoundError as erreur:
        raise _Echec(f"modèles introuvables : {chemin}") from erreur
    except OSError as erreur:
        raise _Echec(f"modèles illisibles : {chemin} ({erreur.strerror})") from erreur
    except ErreurModeles as erreur:
        raise _Echec(f"modèles invalides : {chemin} : {erreur}") from erreur


def _publier(rapport: str, sortie: Path | None) -> None:
    if sortie is None:
        print(rapport, end="")
        return
    try:
        sortie.write_bytes(rapport.encode("utf-8"))
    except OSError as erreur:
        raise _Echec(f"écriture impossible : {sortie} ({erreur.strerror})") from erreur


def _lignes_de_rejets(rejets: Sequence[LigneRejetee]) -> list[str]:
    lignes = [_decrire_rejet(r) for r in rejets[:REJETS_MAX_AFFICHES]]
    autres = len(rejets) - REJETS_MAX_AFFICHES
    if autres > 0:
        lignes.append(f"… et {autres} autre{'s' if autres > 1 else ''}")
    return lignes


def _decrire_rejet(rejet: LigneRejetee) -> str:
    # detail est la valeur fautive lue dans le fichier : contrôlée par l'attaquant.
    detail = neutraliser(rejet.detail)
    return f"ligne {rejet.numero} rejetée : {rejet.raison.value} : {detail}"


def _analyseur() -> argparse.ArgumentParser:
    analyseur = argparse.ArgumentParser(
        prog="sentinelle.py",
        description="Rapport d'Ego sur un export CSV d'événements 4625.",
    )
    analyseur.add_argument("export", type=Path, help="export CSV (Date,Compte,IP)")
    analyseur.add_argument(
        "--modeles",
        type=Path,
        default=MODELES_PAR_DEFAUT,
        metavar="CHEMIN",
        help="fichier des répliques d'Ego (défaut : modeles/ego.json à côté du script)",
    )
    analyseur.add_argument(
        "--sortie",
        type=Path,
        metavar="FICHIER",
        help="écrire le rapport dans ce fichier (UTF-8) plutôt que sur la sortie",
    )
    analyseur.add_argument(
        "--seuil",
        type=_seuil,
        default=SEUIL_ECHECS,
        metavar="N",
        help=f"échecs dans une même fenêtre pour alerter (défaut : {SEUIL_ECHECS})",
    )
    analyseur.add_argument(
        "--fenetre",
        type=_fenetre_en_minutes,
        default=FENETRE // UNE_MINUTE,
        metavar="MINUTES",
        help=(
            "durée de la fenêtre glissante, en minutes entières"
            f" (défaut : 10, maximum : {FENETRE_MAX_MINUTES})"
        ),
    )
    return analyseur


def _entier(texte: str) -> int:
    try:
        return int(texte)
    except ValueError:
        raise argparse.ArgumentTypeError(f"entier attendu, reçu {texte!r}") from None


def _seuil(texte: str) -> int:
    seuil = _entier(texte)
    if seuil < 1:
        raise argparse.ArgumentTypeError(f"au moins 1 attendu, reçu {seuil}")
    return seuil


def _fenetre_en_minutes(texte: str) -> int:
    minutes = _entier(texte)
    if not 1 <= minutes <= FENETRE_MAX_MINUTES:
        raise argparse.ArgumentTypeError(
            f"entre 1 et {FENETRE_MAX_MINUTES} minutes attendu, reçu {minutes}"
        )
    return minutes


if __name__ == "__main__":  # pragma: no cover - exécuté en sous-processus
    sys.exit(main())
