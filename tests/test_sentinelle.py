"""CLI sentinelle.py : appels directs de main() et bout en bout en sous-processus.

Les rapports attendus sont calculés avec la bibliothèque elle-même : aucun test
ne dépend de la formulation des répliques d'ego.json.
"""

import io
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

import sentinelle
from ego.detection import detecter
from ego.lecture import lire_export
from ego.modeles import charger_modeles
from ego.rapport import rediger

RACINE = Path(__file__).parent.parent
EGO = RACINE / "modeles" / "ego.json"
FENETRE = timedelta(minutes=10)


def lancer(capsys, *arguments: object) -> tuple[int | str, str, str]:
    """Code de sortie, stdout et stderr d'un appel à main().

    Une exception non rattrapée (un traceback pour l'utilisateur) devient un
    code « exception … » : les tests échouent alors par assertion.
    """
    try:
        code = sentinelle.main([str(a) for a in arguments])
    except SystemExit as fin:  # argparse
        code = fin.code
    except Exception as erreur:  # noqa: BLE001 - signalée par le code renvoyé
        code = f"exception {type(erreur).__name__}: {erreur}"
    sortie = capsys.readouterr()
    return code, sortie.out, sortie.err


def rapport_attendu(
    export: Path, seuil: int = 5, fenetre: timedelta = FENETRE, modeles: Path = EGO
) -> str:
    lecture = lire_export(export)
    alertes = detecter(lecture.evenements, seuil, fenetre)
    return rediger(alertes, lecture.rejets, seuil, fenetre, charger_modeles(modeles))


class TestRapport:
    def test_rapport_sur_stdout(self, capsys, donnees):
        export = donnees / "export_valide.csv"

        code, sortie, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie, erreurs) == (0, rapport_attendu(export), "")

    def test_alertes_detectees_code_1(self, capsys, donnees):
        export = donnees / "export_attaque.csv"

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie) == (1, rapport_attendu(export))


class TestRejets:
    def test_une_ligne_par_rejet_sur_stderr(self, capsys, donnees):
        export = donnees / "export_malforme.csv"
        attendues = [
            f"ligne {r.numero} rejetée : {r.raison.value} : {r.detail}"
            for r in lire_export(export).rejets
        ]

        _, _, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert len(attendues) == 8
        assert erreurs.splitlines() == attendues

    def test_detail_neutralise_sur_stderr(self, capsys, ecrire_export):
        # La valeur fautive vient du fichier : elle tenterait de colorer le
        # terminal et d'y injecter une fausse ligne.
        export = ecrire_export(
            b'Date,Compte,IP\n"2026-11-03T08:00:00+01:00","bob",'
            b'"\x1b[31m\rligne 9 rejet\xc3\xa9e : faux"\n'
        )

        _, _, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert "\x1b" not in erreurs and "\r" not in erreurs
        assert erreurs.splitlines() == [
            "ligne 2 rejetée : IP invalide : \\x1b[31m\\x0dligne 9 rejetée : faux"
        ]

    @pytest.mark.parametrize(
        ("nombre", "suite"),
        [(20, []), (21, ["… et 1 autre"]), (300, ["… et 280 autres"])],
        ids=["20-tous", "21-un-autre", "300"],
    )
    def test_au_plus_vingt_rejets_puis_et_n_autres(
        self, capsys, ecrire_export, nombre, suite
    ):
        lignes = "".join(
            f'"2026-11-03T08:00:00+01:00","bob","x{n}"\n' for n in range(nombre)
        )
        export = ecrire_export(("Date,Compte,IP\n" + lignes).encode("utf-8"))

        _, _, erreurs = lancer(capsys, export, "--modeles", EGO)

        vingt = [f"ligne {n + 2} rejetée : IP invalide : x{n}" for n in range(20)]
        assert erreurs.splitlines() == vingt + suite


class TestSortie:
    def test_rapport_ecrit_en_utf8_dans_le_fichier(self, capsys, donnees, tmp_path):
        export = donnees / "export_attaque.csv"
        cible = tmp_path / "rapport.txt"

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO, "--sortie", cible)

        assert (code, sortie) == (1, "")
        assert cible.read_bytes() == rapport_attendu(export).encode("utf-8")


class TestErreurs:
    @pytest.mark.parametrize(
        ("cas", "attendu"),
        [
            ("export-absent", "export introuvable : "),
            ("export-vide", "export invalide : "),
            ("modeles-absents", "modèles introuvables : "),
            ("modeles-invalides", "modèles invalides : "),
            ("sortie-impossible", "écriture impossible : "),
            ("export-dossier", "export illisible : "),
            ("modeles-dossier", "modèles illisibles : "),
        ],
    )
    def test_erreur_message_clair_et_code_2(
        self, capsys, tmp_path, donnees, cas, attendu
    ):
        export, modeles = donnees / "export_attaque.csv", EGO
        options = []
        if cas == "export-absent":
            export = tmp_path / "absent.csv"
        elif cas == "export-vide":
            export = tmp_path / "vide.csv"
            export.write_bytes(b"")
        elif cas == "modeles-absents":
            modeles = tmp_path / "absent.json"
        elif cas == "modeles-invalides":
            modeles = tmp_path / "ego.json"
            modeles.write_text('{"entete": [', encoding="utf-8")
        elif cas == "export-dossier":
            export = tmp_path  # OSError autre que « introuvable »
        elif cas == "modeles-dossier":
            modeles = tmp_path
        else:
            options = ["--sortie", tmp_path / "dossier-absent" / "rapport.txt"]

        code, sortie, erreurs = lancer(capsys, export, "--modeles", modeles, *options)

        assert (code, sortie) == (2, "")
        assert erreurs.startswith(f"sentinelle.py : erreur : {attendu}")
        assert erreurs.count("\n") == 1  # une ligne, pas de traceback

    def test_valueerror_de_detecter_message_clair_et_code_2(
        self, capsys, donnees, monkeypatch
    ):
        def refuser(*_args):
            raise ValueError("seuil invalide : 0 (minimum 1)")

        monkeypatch.setattr(sentinelle, "detecter", refuser)

        code, _, erreurs = lancer(capsys, donnees / "export_attaque.csv")

        assert code == 2
        assert erreurs == (
            "sentinelle.py : erreur : paramètres invalides :"
            " seuil invalide : 0 (minimum 1)\n"
        )


class TestValidationDesOptions:
    @pytest.mark.parametrize(
        ("option", "valeur"),
        [
            ("--seuil", "0"),
            ("--seuil", "-1"),
            ("--seuil", "2.5"),
            ("--seuil", "abc"),
            ("--fenetre", "0"),
            ("--fenetre", "-5"),
            ("--fenetre", "1441"),  # au-delà de MARGE_CALCUL (1 jour)
            ("--fenetre", "10.5"),  # minutes entières
            ("--fenetre", "dix"),
        ],
    )
    def test_valeur_refusee_par_argparse(self, capsys, donnees, option, valeur):
        code, sortie, erreurs = lancer(
            capsys, donnees / "export_attaque.csv", option, valeur
        )

        assert (code, sortie) == (2, "")
        assert erreurs.startswith("usage: sentinelle.py")
        assert f"argument {option}" in erreurs

    @pytest.mark.parametrize(
        "options",
        [["--seuil", "1"], ["--fenetre", "1"], ["--fenetre", "1440"]],
        ids=["seuil-1", "fenetre-1", "fenetre-1440"],
    )
    def test_bornes_acceptees(self, capsys, donnees, options):
        code, _, _ = lancer(capsys, donnees / "export_attaque.csv", *options)

        assert code in (0, 1)


def executer(*arguments: object, cwd: Path, env: dict[str, str] | None = None):
    """Lance `python sentinelle.py …` dans un vrai sous-processus (octets bruts)."""
    environnement = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, str(RACINE / "sentinelle.py"), *map(str, arguments)],
        cwd=cwd,
        env=environnement,
        capture_output=True,
        timeout=60,
    )


def sans_cr(octets: bytes) -> bytes:
    """Fins de ligne du système (CRLF sous Windows) ramenées à LF."""
    return octets.replace(b"\r\n", b"\n")


class TestModelesParDefaut:
    def test_cherches_a_cote_du_script_et_non_du_dossier_courant(
        self, donnees, tmp_path
    ):
        # tmp_path ne contient aucun dossier modeles/.
        resultat = executer(donnees / "export_attaque.csv", cwd=tmp_path)

        assert resultat.returncode == 1, resultat.stderr


# Une console ou un pipe Windows en cp1252 : sans précaution, Python y écrirait
# « é » en un octet 0xE9 et lèverait UnicodeEncodeError sur « ā ».
CP1252 = {"PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}


class TestEncodage:
    def test_rapport_et_rejets_en_utf8_meme_si_la_sortie_est_en_cp1252(
        self, tmp_path, ecrire_export
    ):
        modeles = tmp_path / "ego.json"
        modeles.write_text(
            '{"entete": ["Écartée é ā."], "alerte": ["$ip"], "alerte_locale": ["$ip"],'
            ' "rien_a_signaler": ["Rien."], "lignes_rejetees": ["$nombre."],'
            ' "conclusion": ["Fin."]}',
            encoding="utf-8",
        )
        export = ecrire_export(b'Date,Compte,IP\n"2026-11-03T08:00:00Z","bob","-"\n')

        resultat = executer(export, "--modeles", modeles, cwd=tmp_path, env=CP1252)

        assert resultat.returncode == 0, resultat.stderr
        assert resultat.stdout.startswith("Écartée é ā.".encode("utf-8"))
        assert sans_cr(resultat.stderr) == "ligne 2 rejetée : IP absente : -\n".encode(
            "utf-8"
        )


    def test_message_d_argparse_hors_cp1252_sans_traceback(self, donnees, tmp_path):
        resultat = executer(
            donnees / "export_attaque.csv", "--seuil", "ā", cwd=tmp_path, env=CP1252
        )

        assert resultat.returncode == 2
        assert b"Traceback" not in resultat.stderr
        assert "reçu 'ā'".encode("utf-8") in resultat.stderr

    def test_flux_non_reconfigurable_accepte(self, donnees, monkeypatch):
        sortie, erreurs = io.StringIO(), io.StringIO()
        monkeypatch.setattr(sys, "stdout", sortie)
        monkeypatch.setattr(sys, "stderr", erreurs)

        code = sentinelle.main([str(donnees / "export_attaque.csv")])

        assert code == 1
        assert sortie.getvalue() == rapport_attendu(donnees / "export_attaque.csv")


class TestBoutEnBout:
    def test_export_d_attaque(self, donnees, tmp_path):
        export = donnees / "export_attaque.csv"

        resultat = executer(export, cwd=tmp_path, env=CP1252)

        assert resultat.returncode == 1
        assert sans_cr(resultat.stdout) == rapport_attendu(export).encode("utf-8")
        assert sans_cr(resultat.stderr) == "ligne 16 rejetée : IP absente : -\n".encode(
            "utf-8"
        )

    def test_export_sans_alerte_code_0(self, donnees, tmp_path):
        resultat = executer(donnees / "export_valide.csv", cwd=tmp_path, env=CP1252)

        assert (resultat.returncode, resultat.stderr) == (0, b"")

    def test_erreur_code_2_sans_traceback(self, tmp_path):
        resultat = executer(tmp_path / "absent.csv", cwd=tmp_path, env=CP1252)

        assert resultat.returncode == 2
        assert resultat.stdout == b""
        assert sans_cr(resultat.stderr).startswith(
            "sentinelle.py : erreur : export introuvable : ".encode("utf-8")
        )
        assert b"Traceback" not in resultat.stderr


class TestParametres:
    def test_seuil_transmis(self, capsys, donnees):
        # 203.0.113.66 atteint 6 et ::1 atteint 5 : à 6, seule la première reste.
        export = donnees / "export_attaque.csv"

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO, "--seuil", 6)

        assert (code, sortie) == (1, rapport_attendu(export, seuil=6))
        assert "::1" not in sortie and "203.0.113.66" in sortie

    def test_seuil_au_dessus_de_tout_code_0(self, capsys, donnees):
        export = donnees / "export_attaque.csv"

        code, _, _ = lancer(capsys, export, "--modeles", EGO, "--seuil", 7)

        assert code == 0

    def test_fenetre_en_minutes_transmise(self, capsys, donnees):
        # Une fenêtre d'une minute ne contient plus 5 échecs de ::1 (90 s).
        export = donnees / "export_attaque.csv"
        une_minute = timedelta(minutes=1)

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO, "--fenetre", 1)

        assert sortie == rapport_attendu(export, fenetre=une_minute)
        assert "::1" not in sortie
