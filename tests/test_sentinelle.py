"""CLI sentinelle.py : appels directs de main() et bout en bout en sous-processus.

Les rapports attendus sont calculés avec la bibliothèque elle-même : aucun test
ne dépend de la formulation des répliques d'ego.json.
"""

import errno
import io
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path

import pytest

import sentinelle
from ego.detection import detecter
from ego.lecture import lire_export
from ego.modeles import charger_modeles
from ego.rapport import rediger
from ego.rapport_html import CSP, rediger_html

RACINE = Path(__file__).parent.parent
EGO = RACINE / "modeles" / "ego.json"
FENETRE = timedelta(minutes=10)
# Les six clés lues par le rapport texte.
CLES_TEXTE = (
    "entete",
    "alerte",
    "alerte_locale",
    "rien_a_signaler",
    "lignes_rejetees",
    "conclusion",
)


def appeler(*arguments: object, **options: object) -> int | str:
    """Code de sortie d'un appel à main() ; options : arguments nommés de main().

    Une exception non rattrapée (un traceback pour l'utilisateur) devient un
    code « exception … » : les tests échouent alors par assertion.
    """
    try:
        return sentinelle.main([str(a) for a in arguments], **options)
    except SystemExit as fin:  # argparse
        return fin.code
    except (Exception, KeyboardInterrupt) as erreur:  # noqa: BLE001 - voir ci-dessus
        return f"exception {type(erreur).__name__}: {erreur}"


def lancer(capsys, *arguments: object, **options: object) -> tuple[int | str, str, str]:
    """Code de sortie, stdout et stderr d'un appel à main()."""
    code = appeler(*arguments, **options)
    sortie = capsys.readouterr()
    return code, sortie.out, sortie.err


def rapport_attendu(
    export: Path, seuil: int = 5, fenetre: timedelta = FENETRE, modeles: Path = EGO
) -> str:
    lecture = lire_export(export)
    alertes = detecter(lecture.evenements, seuil, fenetre)
    return rediger(alertes, lecture.rejets, seuil, fenetre, charger_modeles(modeles))


def ips_en_alerte(export: Path, seuil: int, fenetre: timedelta) -> list[str]:
    """IP en alerte, calculées sans passer par le texte du rapport."""
    alertes = detecter(lire_export(export).evenements, seuil, fenetre)
    return [str(a.ip) for a in alertes]


class TestRapport:
    def test_rapport_sur_stdout(self, capsys, donnees):
        export = donnees / "export_valide.csv"

        code, sortie, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie, erreurs) == (0, rapport_attendu(export), "")

    def test_alertes_detectees_code_1(self, capsys, donnees):
        export = donnees / "export_attaque.csv"

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie) == (1, rapport_attendu(export))

    def test_alerte_locale_seule_code_1(self, capsys, ecrire_export):
        lignes = "".join(
            f'"2026-11-03T08:0{n}:00+01:00","bob","127.0.0.1"\n' for n in range(5)
        )
        export = ecrire_export(("Date,Compte,IP\n" + lignes).encode("utf-8"))
        alertes = detecter(lire_export(export).evenements, 5, FENETRE)
        assert [a.est_locale for a in alertes] == [True]

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie) == (1, rapport_attendu(export))

    def test_cles_du_rapport_html_sans_effet_sur_le_texte(
        self, capsys, donnees, tmp_path
    ):
        export = donnees / "export_attaque.csv"
        complets = donnees / "modeles_html.json"
        repliques = json.loads(complets.read_text(encoding="utf-8"))
        six_cles = tmp_path / "six_cles.json"
        six_cles.write_text(
            json.dumps({c: v for c, v in repliques.items() if c in CLES_TEXTE}),
            encoding="utf-8",
        )

        code, sortie, _ = lancer(capsys, export, "--modeles", complets)

        assert (code, sortie) == (1, rapport_attendu(export, modeles=six_cles))


def export_de_tirets(ecrire_export, nombre: int) -> Path:
    """`nombre` échecs « - » (origine locale sans IP), une minute d'écart."""
    lignes = "".join(
        f'"2026-11-03T08:0{n}:00+01:00","bob","-"\n' for n in range(nombre)
    )
    return ecrire_export(("Date,Compte,IP\n" + lignes).encode("utf-8"))


class TestOrigineSansIP:
    def test_cinq_tirets_en_dix_minutes_alerte_locale_code_1(
        self, capsys, ecrire_export
    ):
        export = export_de_tirets(ecrire_export, 5)

        code, sortie, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie, erreurs) == (1, rapport_attendu(export), "")
        assert "(local, sans IP)" in sortie

    def test_quatre_tirets_aucune_alerte_et_aucun_rejet(self, capsys, ecrire_export):
        export = export_de_tirets(ecrire_export, 4)

        code, sortie, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert (code, sortie, erreurs) == (0, rapport_attendu(export), "")


class TestRejets:
    def test_une_ligne_par_rejet_sur_stderr(self, capsys, donnees):
        export = donnees / "export_malforme.csv"
        attendues = [
            f"ligne {r.numero} rejetée : {r.raison.value} : {r.detail}"
            for r in lire_export(export).rejets
        ]

        _, _, erreurs = lancer(capsys, export, "--modeles", EGO)

        assert len(attendues) == 7  # la ligne 3, « - », est un événement
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
            # int() accepterait ces formes ; seuls les chiffres 0-9 le sont.
            ("--seuil", " 5"),
            ("--seuil", "+10"),
            ("--seuil", "1_000"),
            ("--seuil", "٥"),  # chiffre arabe-indien 5
            ("--seuil", "1234567890"),  # 10 chiffres
        ],
    )
    def test_valeur_refusee_par_argparse(self, capsys, donnees, option, valeur):
        code, sortie, erreurs = lancer(
            capsys, donnees / "export_attaque.csv", option, valeur
        )

        assert (code, sortie) == (2, "")
        assert erreurs.startswith("usage: sentinelle.py")
        assert f"argument {option}" in erreurs

    def test_valeur_tres_longue_non_recopiee_en_entier(self, capsys, donnees):
        code, _, erreurs = lancer(
            capsys, donnees / "export_attaque.csv", "--seuil", "9" * 5000
        )

        assert code == 2
        assert "argument --seuil" in erreurs
        assert len(erreurs) < 1000

    @pytest.mark.parametrize(
        "options",
        [
            ["--seuil", "1"],
            ["--seuil", "007"],
            ["--fenetre", "1"],
            ["--fenetre", "1440"],
        ],
        ids=["seuil-1", "seuil-007", "fenetre-1", "fenetre-1440"],
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
        export = ecrire_export(b'Date,Compte,IP\n"2026-11-03T08:00:00Z","bob","x"\n')

        resultat = executer(export, "--modeles", modeles, cwd=tmp_path, env=CP1252)

        assert resultat.returncode == 0, resultat.stderr
        assert resultat.stdout.startswith("Écartée é ā.".encode("utf-8"))
        assert sans_cr(resultat.stderr) == "ligne 2 rejetée : IP invalide : x\n".encode(
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
        assert resultat.stderr == b""  # ligne 16, « - » : un événement, plus un rejet

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

        assert ips_en_alerte(export, 6, FENETRE) == ["203.0.113.66"]

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO, "--seuil", 6)

        assert (code, sortie) == (1, rapport_attendu(export, seuil=6))

    def test_seuil_au_dessus_de_tout_code_0(self, capsys, donnees):
        export = donnees / "export_attaque.csv"

        code, _, _ = lancer(capsys, export, "--modeles", EGO, "--seuil", 7)

        assert code == 0

    def test_fenetre_en_minutes_transmise(self, capsys, donnees):
        # Une fenêtre d'une minute ne contient plus 5 échecs de ::1 (90 s).
        export = donnees / "export_attaque.csv"
        une_minute = timedelta(minutes=1)
        assert "::1" in ips_en_alerte(export, 5, FENETRE)
        assert "::1" not in ips_en_alerte(export, 5, une_minute)

        code, sortie, _ = lancer(capsys, export, "--modeles", EGO, "--fenetre", 1)

        assert sortie == rapport_attendu(export, fenetre=une_minute)


class TestDemiCodets:
    def test_modeles_avec_demi_codet_refuses_code_2(self, capsys, donnees, tmp_path):
        modeles = tmp_path / "ego.json"
        modeles.write_text(
            '{"entete": ["Ego \\ud800."], "alerte": ["$ip"], "alerte_locale": ["$ip"],'
            ' "rien_a_signaler": ["Rien."], "lignes_rejetees": ["$nombre."],'
            ' "conclusion": ["Fin."]}',
            encoding="utf-8",
        )

        code, sortie, erreurs = lancer(
            capsys, donnees / "export_attaque.csv", "--modeles", modeles
        )

        assert (code, sortie) == (2, "")
        assert erreurs.startswith("sentinelle.py : erreur : modèles invalides : ")

    @pytest.mark.parametrize("vers_fichier", [False, True], ids=["stdout", "sortie"])
    def test_rapport_non_encodable_code_2_sans_rien_ecrire(
        self, capsys, donnees, tmp_path, monkeypatch, vers_fichier
    ):
        # Défense en profondeur : le chargement des modèles refuse déjà ce cas.
        monkeypatch.setattr(sentinelle, "rediger", lambda *_args: "Ego \ud800.\n")
        cible = tmp_path / "rapport.txt"
        options = ["--sortie", cible] if vers_fichier else []

        code, sortie, erreurs = lancer(capsys, donnees / "export_attaque.csv", *options)

        assert (code, sortie, cible.exists()) == (2, "", False)
        assert erreurs == (
            "sentinelle.py : erreur : rapport impossible à écrire en UTF-8"
            " (demi-codet isolé \\ud800)\n"
        )

    def test_demi_codet_sur_stderr_echappe_sans_traceback(self, donnees, monkeypatch):
        # Une ligne de commande Windows peut contenir un demi-codet isolé, et
        # argparse le recopie tel quel dans son message d'erreur.
        erreurs = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", write_through=True)
        monkeypatch.setattr(sys, "stderr", erreurs)

        code = appeler(donnees / "export_attaque.csv", "\ud800")

        assert code == 2
        assert b"unrecognized arguments: \\ud800" in erreurs.buffer.getvalue()


class _TubeFerme(io.RawIOBase):
    """Sortie standard dont le lecteur a disparu (pipe fermé, `head`…)."""

    def __init__(self) -> None:
        super().__init__()
        self.ferme = True

    def writable(self) -> bool:
        return True

    def write(self, octets) -> int:
        if self.ferme:
            raise OSError(errno.EINVAL, "Invalid argument")
        return len(octets)


def export_avec_un_rejet(ecrire_export) -> Path:
    """Une ligne exploitable, puis une ligne rejetée (ligne 3, IP invalide)."""
    return ecrire_export(
        b"Date,Compte,IP\n"
        b'"2026-11-03T08:00:00+01:00","alice","192.0.2.10"\n'
        b'"2026-11-03T08:01:00+01:00","bob","pas-une-ip"\n'
    )


class TestSortieStandardEnErreur:
    def test_code_2_message_et_rejets_affiches(self, capsys, ecrire_export, monkeypatch):
        tube = _TubeFerme()
        stdout = io.TextIOWrapper(io.BufferedWriter(tube), encoding="utf-8")
        monkeypatch.setattr(sys, "stdout", stdout)

        code = appeler(export_avec_un_rejet(ecrire_export))

        tube.ferme = False  # laisse le ramasse-miettes vider le tampon sans erreur
        assert code == 2
        assert capsys.readouterr().err.splitlines() == [
            "ligne 3 rejetée : IP invalide : pas-une-ip",
            "sentinelle.py : erreur : écriture impossible sur la sortie standard"
            " (Invalid argument)",
        ]

    def test_stdout_absent_code_2(self, capsys, donnees, monkeypatch):
        # Python met sys.stdout à None si le descripteur 1 est fermé au lancement.
        monkeypatch.setattr(sys, "stdout", None)

        code = appeler(donnees / "export_attaque.csv")

        assert code == 2
        assert capsys.readouterr().err.endswith(
            "sentinelle.py : erreur : écriture impossible sur la sortie standard"
            " (fermée)\n"
        )

    def test_vrai_tube_ferme_code_2_sans_traceback(self, tmp_path, ecrire_export):
        export = export_avec_un_rejet(ecrire_export)
        lecture, ecriture = os.pipe()
        os.close(lecture)  # personne ne lira : toute écriture échoue
        try:
            resultat = subprocess.run(
                [sys.executable, str(RACINE / "sentinelle.py"), str(export)],
                cwd=tmp_path,
                env={**os.environ, **CP1252},
                stdout=ecriture,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        finally:
            os.close(ecriture)

        lignes = sans_cr(resultat.stderr).decode("utf-8").splitlines()
        assert resultat.returncode == 2, lignes
        assert lignes[0] == "ligne 3 rejetée : IP invalide : pas-une-ip"
        assert lignes[1].startswith(
            "sentinelle.py : erreur : écriture impossible sur la sortie standard"
        )
        assert len(lignes) == 2, lignes  # ni traceback ni « Exception ignored »


class TestSortieProtegee:
    @pytest.mark.parametrize(
        ("protege", "attendu"),
        [("export", "l'export"), ("modeles", "le fichier de modèles")],
    )
    def test_sortie_identique_refusee_sans_ecraser(
        self, capsys, donnees, tmp_path, protege, attendu
    ):
        export = tmp_path / "export.csv"
        export.write_bytes((donnees / "export_attaque.csv").read_bytes())
        modeles = tmp_path / "ego.json"
        modeles.write_bytes(EGO.read_bytes())  # copie : le vrai ego.json reste intact
        cible = export if protege == "export" else modeles
        avant = cible.read_bytes()
        (tmp_path / "sous").mkdir()
        autre_graphie = tmp_path / "sous" / ".." / cible.name

        code, sortie, erreurs = lancer(
            capsys, export, "--modeles", modeles, "--sortie", autre_graphie
        )

        assert (code, sortie) == (2, "")
        assert cible.read_bytes() == avant
        assert erreurs.startswith(
            f"sentinelle.py : erreur : --sortie écraserait {attendu} : "
        )
        assert erreurs.count("\n") == 1


PIEGE = "piege\x1b]0;pwn\x07\u202e.csv"
PIEGE_NEUTRALISE = "piege\\x1b]0;pwn\\x07\\u202e.csv"


class TestCheminsNeutralises:
    @pytest.mark.parametrize("option", ["export", "--modeles", "--sortie", "--html"])
    def test_chemin_piege_neutralise_dans_le_message(
        self, capsys, donnees, tmp_path, option
    ):
        piege = tmp_path / PIEGE
        export, modeles, options = donnees / "export_attaque.csv", EGO, []
        if option == "export":
            export = piege
        elif option == "--modeles":
            modeles = piege
        else:
            # La sortie doit échouer sur tous les systèmes. Linux accepte ce nom :
            # un dossier de ce nom fait échouer l'écriture. Windows interdit les
            # caractères de contrôle : mkdir échoue, et l'écriture aussi.
            try:
                piege.mkdir()
            except OSError:
                assert os.name == "nt", "seul Windows refuse ce nom de dossier"
            options = [option, piege]

        code, _, erreurs = lancer(capsys, export, "--modeles", modeles, *options)

        assert code == 2
        assert not {"\x1b", "\x07", "\u202e"} & set(erreurs)
        assert f"{tmp_path.as_posix()}/{PIEGE_NEUTRALISE}" in erreurs
        assert erreurs.count("\n") == 1


class TestInterruption:
    def test_ctrl_c_code_130_sans_traceback(self, capsys, donnees, monkeypatch):
        def interrompre(*_args):
            raise KeyboardInterrupt

        monkeypatch.setattr(sentinelle, "detecter", interrompre)

        code, sortie, erreurs = lancer(capsys, donnees / "export_attaque.csv")

        assert (code, sortie, erreurs) == (130, "", "")


# --html : l'horloge est injectée, le rapport attendu se calcule donc exactement.
PLUS_UNE = timezone(timedelta(hours=1))
GENERE_LE = datetime(2026, 11, 3, 10, 0, tzinfo=PLUS_UNE)
WINDOWS = os.name == "nt"
DEMI_CODET = chr(0xD800)


def horloge_fixe() -> datetime:
    return GENERE_LE


def html_attendu(
    export: Path,
    *,
    total_echecs: int,
    origines: int,
    periode: tuple[datetime, datetime] | None,
    seuil: int = 5,
    fenetre: timedelta = FENETRE,
) -> bytes:
    """Rapport HTML attendu. L'en-tête est donné en clair, pas recalculé comme la CLI."""
    lecture = lire_export(export)
    alertes = detecter(lecture.evenements, seuil, fenetre)
    document = rediger_html(
        alertes,
        lecture.rejets,
        seuil,
        fenetre,
        charger_modeles(EGO),
        total_echecs=total_echecs,
        origines=origines,
        periode=periode,
        source=export,
        genere_le=GENERE_LE,
    )
    return document.encode("utf-8")


class Structure(HTMLParser):
    """Lecture par html.parser : balises <meta>, et imbrication vérifiée."""

    VIDES = frozenset({"meta"})  # seule balise vide du rapport (<path/> se ferme seul)

    def __init__(self, document: str) -> None:
        super().__init__(convert_charrefs=True)
        self.pile: list[str] = []
        self.erreurs: list[str] = []
        self.metas: list[dict[str, str | None]] = []
        self.feed(document)
        self.close()

    def handle_starttag(self, balise, attributs):
        if balise == "meta":
            self.metas.append(dict(attributs))
        if balise not in self.VIDES:
            self.pile.append(balise)

    def handle_endtag(self, balise):
        if not self.pile or self.pile.pop() != balise:
            self.erreurs.append(f"</{balise}> inattendue")


ATTAQUE = {
    "total_echecs": 15,
    "origines": 4,  # 203.0.113.66, 192.0.2.20, ::1, (local, sans IP)
    "periode": (
        datetime(2026, 11, 3, 2, 14, 5, 100000, tzinfo=PLUS_UNE),
        datetime(2026, 11, 3, 9, 5, tzinfo=PLUS_UNE),  # ligne 16, « - »
    ),
}


class TestRapportHtml:
    def test_bout_en_bout_export_d_attaque(self, donnees, tmp_path):
        export = donnees / "export_attaque.csv"
        cible = tmp_path / "rapport.html"

        resultat = executer(export, "--html", cible, cwd=tmp_path, env=CP1252)

        # Horloge réelle : un genere_le sans fuseau lèverait ValueError (traceback).
        assert resultat.returncode == 1
        assert resultat.stderr == b""  # ligne 16, « - » : un événement, plus un rejet
        assert sans_cr(resultat.stdout) == rapport_attendu(export).encode("utf-8")
        assert cible.is_file()
        octets = cible.read_bytes()
        assert not octets.startswith(b"\xef\xbb\xbf")  # UTF-8 sans BOM
        document = octets.decode("utf-8")
        structure = Structure(document)
        assert (structure.erreurs, structure.pile) == ([], [])
        assert {"http-equiv": "Content-Security-Policy", "content": CSP} in (
            structure.metas
        )
        assert '<body class="etat-alerte">' in document

    @pytest.mark.parametrize(
        ("options", "seuil", "fenetre"),
        [([], 5, FENETRE), (["--seuil", 6, "--fenetre", 20], 6, timedelta(minutes=20))],
        ids=["defaut", "seuil-fenetre"],
    )
    def test_contenu_egal_a_rediger_html(
        self, capsys, donnees, tmp_path, options, seuil, fenetre
    ):
        export = donnees / "export_attaque.csv"
        cible = tmp_path / "rapport.html"

        code, _, _ = lancer(
            capsys, export, *options, "--html", cible, horloge=horloge_fixe
        )

        assert code == 1
        assert cible.is_file()
        assert cible.read_bytes() == html_attendu(
            export, **ATTAQUE, seuil=seuil, fenetre=fenetre
        )

    def test_export_valide_etat_silence(self, capsys, donnees, tmp_path):
        export = donnees / "export_valide.csv"
        cible = tmp_path / "rapport.html"

        code, _, _ = lancer(capsys, export, "--html", cible, horloge=horloge_fixe)

        assert code == 0
        assert cible.is_file()
        octets = cible.read_bytes()
        assert octets == html_attendu(
            export,
            total_echecs=6,
            origines=4,  # 192.0.2.10, 203.0.113.7, ::1, 127.0.0.1
            periode=(
                datetime(2026, 11, 3, 8, 12, 45, 123456, tzinfo=PLUS_UNE),
                datetime(2026, 11, 3, 9, 30, tzinfo=PLUS_UNE),
            ),
        )
        assert '<body class="etat-silence">' in octets.decode("utf-8")
        assert "SILENCE · CODE 0" in octets.decode("utf-8")

    def test_periode_du_plus_ancien_au_plus_recent_et_source_sans_chemin(
        self, capsys, tmp_path, ecrire_export
    ):
        # Lignes non triées : la première et la dernière ne bornent pas la période.
        export = ecrire_export(
            b"Date,Compte,IP\n"
            b'"2026-11-03T09:00:00+01:00","a","192.0.2.1"\n'
            b'"2026-11-03T07:00:00Z","b","192.0.2.2"\n'
            b'"2026-11-03T10:30:00+01:00","c","192.0.2.1"\n'
            b'"2026-11-03T09:15:00+01:00","d","192.0.2.1"\n',
            nom="non_trie.csv",
        )
        cible = tmp_path / "rapport.html"

        code, _, _ = lancer(capsys, export, "--html", cible, horloge=horloge_fixe)

        assert code == 0
        assert cible.is_file()
        octets = cible.read_bytes()
        assert octets == html_attendu(
            export,
            total_echecs=4,
            origines=2,
            periode=(
                datetime(2026, 11, 3, 7, 0, tzinfo=timezone.utc),
                datetime(2026, 11, 3, 10, 30, tzinfo=PLUS_UNE),
            ),
        )
        document = octets.decode("utf-8")
        assert "non_trie.csv" in document
        assert tmp_path.name not in document  # jamais le chemin du dossier

    def test_aucun_evenement_periode_absente(self, capsys, tmp_path, ecrire_export):
        # IP vide : rejetée. (« - » serait un événement : l'origine locale sans IP.)
        export = ecrire_export(b'Date,Compte,IP\n"2026-11-03T08:00:00Z","bob",""\n')
        cible = tmp_path / "rapport.html"

        code, _, _ = lancer(capsys, export, "--html", cible, horloge=horloge_fixe)

        assert code == 0
        assert cible.is_file()
        assert cible.read_bytes() == html_attendu(
            export, total_echecs=0, origines=0, periode=None
        )

    @pytest.mark.parametrize(
        "nom", ["export_attaque.csv", "export_valide.csv", "export_malforme.csv"]
    )
    @pytest.mark.parametrize("avec_sortie", [False, True], ids=["stdout", "sortie"])
    def test_memes_sorties_avec_et_sans_html(
        self, capsys, donnees, tmp_path, nom, avec_sortie
    ):
        export = donnees / nom

        def sortie(nom_fichier: str) -> list[object]:
            return ["--sortie", tmp_path / nom_fichier] if avec_sortie else []

        sans = lancer(capsys, export, *sortie("sans.txt"))
        avec = lancer(
            capsys,
            export,
            *sortie("avec.txt"),
            "--html",
            tmp_path / "rapport.html",
            horloge=horloge_fixe,
        )

        assert avec == sans
        assert (tmp_path / "rapport.html").is_file()
        if avec_sortie:
            assert (tmp_path / "avec.txt").read_bytes() == (
                tmp_path / "sans.txt"
            ).read_bytes()

    def test_horloge_appelee_seulement_avec_html(self, capsys, donnees, tmp_path):
        export = donnees / "export_attaque.csv"
        appels = []

        def horloge() -> datetime:
            appels.append(GENERE_LE)
            return GENERE_LE

        sans, _, _ = lancer(capsys, export, horloge=horloge)
        assert (sans, appels) == (1, [])

        avec, _, _ = lancer(
            capsys, export, "--html", tmp_path / "rapport.html", horloge=horloge
        )
        assert (avec, appels) == (1, [GENERE_LE])

    @pytest.mark.parametrize("option", ["--sortie", "--html"])
    def test_fichier_existant_ecrase_sans_confirmation(
        self, capsys, donnees, tmp_path, option
    ):
        export = donnees / "export_attaque.csv"
        cible = tmp_path / "ancien"
        cible.write_bytes(b"ancien contenu")

        code, _, _ = lancer(capsys, export, option, cible, horloge=horloge_fixe)

        assert code == 1
        attendu = (
            rapport_attendu(export).encode("utf-8")
            if option == "--sortie"
            else html_attendu(export, **ATTAQUE)
        )
        assert cible.read_bytes() == attendu


class TestHtmlProtege:
    @pytest.mark.parametrize(
        ("protege", "attendu"),
        [("export", "l'export"), ("modeles", "le fichier de modèles")],
    )
    def test_html_vers_un_fichier_protege_refuse_sans_ecraser(
        self, capsys, donnees, tmp_path, protege, attendu
    ):
        export = tmp_path / "export.csv"
        export.write_bytes((donnees / "export_attaque.csv").read_bytes())
        modeles = tmp_path / "ego.json"
        modeles.write_bytes(EGO.read_bytes())  # copie : le vrai ego.json reste intact
        cible = export if protege == "export" else modeles
        avant = cible.read_bytes()
        (tmp_path / "sous").mkdir()
        autre_graphie = tmp_path / "sous" / ".." / cible.name

        code, sortie, erreurs = lancer(
            capsys,
            export,
            "--modeles",
            modeles,
            "--html",
            autre_graphie,
            horloge=horloge_fixe,
        )

        assert (code, sortie) == (2, "")
        assert cible.read_bytes() == avant
        assert erreurs == (
            f"sentinelle.py : erreur : --html écraserait {attendu} :"
            f" {autre_graphie.as_posix()}\n"
        )

    @pytest.mark.parametrize("existe", [False, True], ids=["absent", "existant"])
    @pytest.mark.parametrize(
        ("cas", "graphie"),
        [
            ("identique", "rapport.html"),
            ("detour", "sous/../rapport.html"),
            # Mêmes fichiers sous Windows seulement : Linux distingue ces noms.
            ("casse", "RAPPORT.HTML"),
            ("point-final", "rapport.html."),
        ],
    )
    def test_html_et_sortie_sur_le_meme_fichier_refuses(
        self, capsys, donnees, tmp_path, cas, graphie, existe
    ):
        (tmp_path / "sous").mkdir()
        sortie = tmp_path / "rapport.html"
        if existe:
            sortie.write_bytes(b"ancien contenu")
        html = tmp_path / graphie

        code, stdout, erreurs = lancer(
            capsys,
            donnees / "export_attaque.csv",
            "--sortie",
            sortie,
            "--html",
            html,
            horloge=horloge_fixe,
        )

        if cas in ("casse", "point-final") and not WINDOWS:
            assert code == 1  # deux fichiers distincts, tous deux écrits
            return
        assert (code, stdout) == (2, "")
        assert erreurs == (
            "sentinelle.py : erreur : --html et --sortie désignent le même fichier :"
            f" {html.as_posix()}\n"
        )
        restants = sorted(p.name for p in tmp_path.iterdir())
        assert restants == (["rapport.html", "sous"] if existe else ["sous"])
        if existe:
            assert sortie.read_bytes() == b"ancien contenu"


class TestHtmlErreurs:
    @pytest.mark.parametrize("avec_sortie", [False, True], ids=["stdout", "sortie"])
    def test_dossier_absent_message_clair_avant_toute_autre_sortie(
        self, capsys, donnees, tmp_path, avec_sortie
    ):
        texte = tmp_path / "rapport.txt"
        html = tmp_path / "dossier-absent" / "rapport.html"
        options = ["--sortie", texte] if avec_sortie else []

        code, sortie, erreurs = lancer(
            capsys,
            donnees / "export_attaque.csv",
            *options,
            "--html",
            html,
            horloge=horloge_fixe,
        )

        assert (code, sortie) == (2, "")
        assert erreurs.startswith(
            f"sentinelle.py : erreur : écriture impossible : {html.as_posix()} ("
        )
        assert erreurs.count("\n") == 1  # ni ligne rejetée, ni traceback
        assert not texte.exists()

    @pytest.mark.parametrize("option", ["--sortie", "--html"])
    def test_cible_dossier_existant_message_clair(
        self, capsys, donnees, tmp_path, option
    ):
        dossier = tmp_path / "dossier"
        dossier.mkdir()

        code, sortie, erreurs = lancer(
            capsys,
            donnees / "export_attaque.csv",
            option,
            dossier,
            horloge=horloge_fixe,
        )

        assert (code, sortie) == (2, "")
        assert erreurs == (
            "sentinelle.py : erreur : écriture impossible :"
            f" {dossier.as_posix()} (c'est un dossier)\n"
        )
        assert list(dossier.iterdir()) == []

    @pytest.mark.parametrize(
        "cas",
        [
            "export-absent",
            "modeles-invalides",
            "detection",
            "encodage-texte",
            "encodage-html",
        ],
    )
    def test_aucun_fichier_ecrit_si_une_etape_echoue(
        self, capsys, donnees, tmp_path, monkeypatch, cas
    ):
        export, modeles = donnees / "export_attaque.csv", EGO
        if cas == "export-absent":
            export = tmp_path / "absent.csv"
        elif cas == "modeles-invalides":
            modeles = tmp_path / "ego.json"
            modeles.write_text('{"entete": [', encoding="utf-8")
        elif cas == "detection":

            def refuser(*_args):
                raise ValueError("seuil invalide : 0 (minimum 1)")

            monkeypatch.setattr(sentinelle, "detecter", refuser)
        elif cas == "encodage-texte":
            monkeypatch.setattr(sentinelle, "rediger", lambda *_a, **_k: DEMI_CODET)
        else:
            # raising=False : l'attribut n'existe pas avant l'implémentation ; un
            # nom erroné ferait échouer le test (code 1 au lieu de 2).
            monkeypatch.setattr(
                sentinelle, "rediger_html", lambda *_a, **_k: DEMI_CODET, raising=False
            )
        texte, html = tmp_path / "rapport.txt", tmp_path / "rapport.html"

        code, sortie, erreurs = lancer(
            capsys,
            export,
            "--modeles",
            modeles,
            "--sortie",
            texte,
            "--html",
            html,
            horloge=horloge_fixe,
        )

        assert (code, sortie) == (2, "")
        assert erreurs.startswith("sentinelle.py : erreur : ")
        assert erreurs.count("\n") == 1
        assert (texte.exists(), html.exists()) == (False, False)
