"""Ego Sentinelle : rapport d'Ego sur un export d'échecs de connexion 4625."""

import argparse
import io
import os
import re
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path

from ego._redaction import REJETS_MAX_AFFICHES
from ego.detection import FENETRE, SEUIL_ECHECS, detecter
from ego.lecture import (
    MARGE_CALCUL,
    ErreurFormat,
    Evenement,
    LigneRejetee,
    ResultatLecture,
    lire_export,
)
from ego.modeles import ErreurModeles, Modeles, charger_modeles
from ego.neutralisation import neutraliser
from ego.rapport import rediger
from ego.rapport_html import rediger_html

# À côté du script, et non dans le dossier courant : sentinelle.py doit
# fonctionner lancé depuis n'importe où.
MODELES_PAR_DEFAUT = Path(__file__).resolve().parent / "modeles" / "ego.json"

CODE_AUCUNE_ALERTE = 0
CODE_ALERTES = 1
CODE_ERREUR = 2
CODE_INTERRUPTION = 130  # convention des shells : 128 + SIGINT (2)

UNE_MINUTE = timedelta(minutes=1)
# Au-delà, les calculs sur les dates acceptées à la lecture pourraient déborder.
FENETRE_MAX_MINUTES = MARGE_CALCUL // UNE_MINUTE

# Options numériques : chiffres ASCII seulement. int() accepterait « +5 »,
# « 1_000 », « ٥ » ou des milliers de chiffres.
CHIFFRES_MAX = 9
ENTIER_OPTION = re.compile(rf"[0-9]{{1,{CHIFFRES_MAX}}}")
# Une valeur refusée est recopiée dans le message, mais pas au-delà.
ECHO_MAX = 20


class _Echec(Exception):
    """Erreur signalée à l'utilisateur par un message, jamais par un traceback."""


def _maintenant() -> datetime:
    return datetime.now().astimezone()


def main(
    argv: Sequence[str] | None = None,
    *,
    horloge: Callable[[], datetime] = _maintenant,
) -> int:
    """Point d'entrée. Codes : 0 aucune alerte, 1 alertes, 2 erreur, 130 Ctrl+C.

    horloge donne l'instant de génération du rapport HTML (injectable pour les
    tests) ; elle n'est appelée qu'avec --html.
    """
    _sorties_en_utf8()
    try:
        return _executer(_analyseur().parse_args(argv), horloge)
    except _Echec as echec:
        print(f"sentinelle.py : erreur : {echec}", file=sys.stderr)
        return CODE_ERREUR
    except KeyboardInterrupt:
        # Interruption voulue par l'opérateur : ni message ni traceback.
        return CODE_INTERRUPTION


def _sorties_en_utf8() -> None:
    # Vers un pipe ou une redirection, Python encode par défaut selon la
    # page de code Windows (cp1252) : « é » deviendrait 0xE9 et « ā » lèverait
    # UnicodeEncodeError. Le rapport et les messages sortent toujours en UTF-8.
    # errors est explicite : reconfigure(encoding=…) le remettrait à « strict ».
    # stdout reste strict, le rapport étant vérifié avant écriture (_encoder) ;
    # stderr échappe ce qu'argparse recopie de la ligne de commande (demi-codet).
    for flux, erreurs in ((sys.stdout, "strict"), (sys.stderr, "backslashreplace")):
        if isinstance(flux, io.TextIOWrapper):
            flux.reconfigure(encoding="utf-8", errors=erreurs)


def _executer(arguments: argparse.Namespace, horloge: Callable[[], datetime]) -> int:
    seuil = arguments.seuil
    fenetre = arguments.fenetre * UNE_MINUTE
    lecture = _lire_export(arguments.export)
    modeles = _charger_modeles(arguments.modeles)
    _proteger_les_sorties(arguments)
    try:
        alertes = detecter(lecture.evenements, seuil, fenetre)
    except ValueError as erreur:
        raise _Echec(f"paramètres invalides : {erreur}") from erreur
    rapport = rediger(alertes, lecture.rejets, seuil, fenetre, modeles)
    # Tout est encodé avant la première écriture : en cas d'échec, rien n'est
    # écrit nulle part. Le HTML est écrit en premier : s'il échoue, ni rejets ni
    # rapport ne sont sortis, et la seule ligne de stderr est l'erreur.
    contenu = _encoder(rapport)
    if arguments.html is not None:
        evenements = lecture.evenements
        document = rediger_html(
            alertes,
            lecture.rejets,
            seuil,
            fenetre,
            modeles,
            total_echecs=len(evenements),
            origines=len({e.ip for e in evenements}),
            periode=_periode(evenements),
            source=arguments.export,
            genere_le=horloge(),
        )
        _ecrire_fichier(arguments.html, _encoder(document))
    _publier(rapport, contenu, lecture.rejets, arguments.sortie)
    return CODE_ALERTES if alertes else CODE_AUCUNE_ALERTE


def _periode(evenements: Sequence[Evenement]) -> tuple[datetime, datetime] | None:
    """Du plus ancien au plus récent événement : l'export n'est pas forcément trié."""
    instants = [e.horodatage for e in evenements]
    return (min(instants), max(instants)) if instants else None


def _lire_export(chemin: Path) -> ResultatLecture:
    try:
        return lire_export(chemin)
    except FileNotFoundError as erreur:
        raise _Echec(f"export introuvable : {_affichable(chemin)}") from erreur
    except OSError as erreur:
        raise _Echec(
            f"export illisible : {_affichable(chemin)} ({erreur.strerror})"
        ) from erreur
    except ErreurFormat as erreur:
        raise _Echec(f"export invalide : {_affichable(chemin)} : {erreur}") from erreur


def _charger_modeles(chemin: Path) -> Modeles:
    try:
        return charger_modeles(chemin)
    except FileNotFoundError as erreur:
        raise _Echec(f"modèles introuvables : {_affichable(chemin)}") from erreur
    except OSError as erreur:
        raise _Echec(
            f"modèles illisibles : {_affichable(chemin)} ({erreur.strerror})"
        ) from erreur
    except ErreurModeles as erreur:
        raise _Echec(
            f"modèles invalides : {_affichable(chemin)} : {erreur}"
        ) from erreur


def _affichable(chemin: Path) -> str:
    # Un nom de fichier peut venir d'un dossier déposé par un tiers (glob *.csv) :
    # il est neutralisé comme toute donnée non fiable. as_posix : sous Windows,
    # des « / » plutôt que des « \ », que neutraliser doublerait.
    return neutraliser(chemin.as_posix())


def _proteger_les_sorties(arguments: argparse.Namespace) -> None:
    sorties = (("--sortie", arguments.sortie), ("--html", arguments.html))
    for option, cible in sorties:
        if cible is not None:
            _proteger(option, cible, arguments.export, arguments.modeles)
    if (
        arguments.sortie is not None
        and arguments.html is not None
        and _meme_fichier(arguments.html, arguments.sortie)
    ):
        raise _Echec(
            "--html et --sortie désignent le même fichier :"
            f" {_affichable(arguments.html)}"
        )


def _proteger(option: str, cible: Path, export: Path, modeles: Path) -> None:
    """Refuse une cible qui écraserait l'export ou les répliques écrites à la main."""
    for chemin, nom in ((export, "l'export"), (modeles, "le fichier de modèles")):
        if _meme_fichier(cible, chemin):
            raise _Echec(f"{option} écraserait {nom} : {_affichable(cible)}")


def _meme_fichier(un: Path, autre: Path) -> bool:
    # samefile compare les fichiers eux-mêmes, quelle que soit la graphie
    # (« .. », casse sous Windows, lien). Si l'un des deux n'existe pas encore
    # (--html et --sortie avant leur première écriture), on compare les chemins
    # normalisés : abspath retire le point ou l'espace final que Windows ignore
    # (« a.html. » est « a.html »), realpath suit les liens, normcase ignore la
    # casse sous Windows seulement.
    try:
        return un.samefile(autre)
    except OSError:
        return _chemin_normalise(un) == _chemin_normalise(autre)


def _chemin_normalise(chemin: Path) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(chemin)))


def _publier(
    rapport: str, contenu: bytes, rejets: Sequence[LigneRejetee], sortie: Path | None
) -> None:
    """contenu : le rapport déjà encodé par _encoder, écrit tel quel dans sortie."""
    if sortie is not None:
        _ecrire_fichier(sortie, contenu)
    # Rejets avant le rapport sur stdout : si personne ne lit stdout (pipe
    # fermé), ils restent visibles.
    for ligne in _lignes_de_rejets(rejets):
        print(ligne, file=sys.stderr)
    if sortie is None:
        _ecrire_sur_stdout(rapport)


def _encoder(rapport: str) -> bytes:
    # Avant toute écriture : en cas d'échec, rien n'est écrit nulle part.
    try:
        return rapport.encode("utf-8")
    except UnicodeEncodeError as erreur:
        fautif = neutraliser(erreur.object[erreur.start])
        raise _Echec(
            f"rapport impossible à écrire en UTF-8 (demi-codet isolé {fautif})"
        ) from erreur


def _ecrire_fichier(cible: Path, contenu: bytes) -> None:
    try:
        cible.write_bytes(contenu)
    except OSError as erreur:
        # Sous Windows, ouvrir un dossier en écriture donne « Permission denied » :
        # la vraie raison est plus claire.
        raison = "c'est un dossier" if cible.is_dir() else erreur.strerror
        raise _Echec(
            f"écriture impossible : {_affichable(cible)} ({raison})"
        ) from erreur


def _ecrire_sur_stdout(rapport: str) -> None:
    if sys.stdout is None:  # descripteur 1 fermé dès le lancement
        raise _Echec("écriture impossible sur la sortie standard (fermée)")
    try:
        print(rapport, end="")
        sys.stdout.flush()
    except OSError as erreur:
        _abandonner_stdout()
        raise _Echec(
            f"écriture impossible sur la sortie standard ({erreur.strerror})"
        ) from erreur


def _abandonner_stdout() -> None:
    # Le tampon de stdout garde le rapport non écrit : en quittant, Python le
    # revide, échoue de nouveau et sort avec le code 120. Rediriger le
    # descripteur vers le périphérique nul rend ce dernier vidage inoffensif.
    # Nettoyage au mieux : l'erreur d'origine est déjà signalée par l'appelant.
    try:
        descripteur = sys.stdout.fileno()
        nul = os.open(os.devnull, os.O_WRONLY)
    except (OSError, ValueError):  # flux sans descripteur (remplacé, tests)
        return
    try:
        os.dup2(nul, descripteur)
    except OSError:
        pass  # descripteur inutilisable : le vidage final échouera, sans plus
    finally:
        os.close(nul)


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
        "--html",
        type=Path,
        metavar="FICHIER",
        help="écrire aussi le rapport HTML dans ce fichier (UTF-8)",
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
    if not ENTIER_OPTION.fullmatch(texte):
        apercu = texte if len(texte) <= ECHO_MAX else texte[:ECHO_MAX] + "…"
        raise argparse.ArgumentTypeError(
            f"entier attendu (chiffres 0-9, {CHIFFRES_MAX} au plus), reçu {apercu!r}"
        )
    return int(texte)


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
