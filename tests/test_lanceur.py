"""Lanceur à double-clic : ego-sentinelle.cmd et lancer.ps1.

Deux familles de tests :
- statiques (octets et texte des fichiers) : sur tous les systèmes ;
- PowerShell : les fonctions de lancer.ps1, appelées par tests/pilote_lanceur.ps1
  dans un vrai Windows PowerShell 5.1. Sous Windows seulement.

Aucun test ne déclenche d'UAC ni n'ouvre de navigateur. Par précaution, chaque
powershell.exe est lancé avec un PATH sans Python et un LOCALAPPDATA temporaire :
un déroulé lancé par erreur s'arrêterait avant l'élévation, sans rien écrire
chez l'utilisateur.
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

RACINE = Path(__file__).parent.parent
CMD = RACINE / "ego-sentinelle.cmd"
LANCEUR = RACINE / "lancer.ps1"
PILOTE = RACINE / "tests" / "pilote_lanceur.ps1"
EXPORT = RACINE / "export-4625.ps1"
BOM = b"\xef\xbb\xbf"

SYSTEME = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
POWERSHELL = SYSTEME / "WindowsPowerShell" / "v1.0" / "powershell.exe"
sous_windows = pytest.mark.skipif(
    os.name != "nt", reason="le lanceur est propre à Windows (powershell.exe)"
)


def avec_powershell(cible):
    """Test ou classe qui lance powershell.exe : lent, et propre à Windows.

    Le marqueur « powershell » (déclaré dans pyproject.toml) permet la suite
    rapide : pytest -m "not powershell".
    """
    return pytest.mark.powershell(sous_windows(cible))


MAINTENANT = "2026-11-10T14:30:05"
# Calendrier hégirien par défaut : sans culture invariante, l'année serait 1448.
CULTURE_PIEGE = "ar-SA"
# Espace, apostrophe, « & », parenthèses (demandés), et ce que cmd ou PowerShell
# interpréteraient s'ils relisaient la ligne de commande : $ ; ` % ^, un accent.
DOSSIER_PIEGE = "Ego l'essai & (copie) é $x;`y %PATH% ^"


def texte_de(chemin: Path) -> str:
    """Texte d'un script, sans BOM, fins de ligne ramenées à LF."""
    return chemin.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")


def environnement(tmp_path: Path, chemin: tuple[Path, ...] = ()) -> dict[str, str]:
    """PATH réduit à Windows (ni py ni python), LOCALAPPDATA temporaire."""
    local = tmp_path / "LocalAppData"
    local.mkdir(exist_ok=True)
    dossiers = [*chemin, SYSTEME, POWERSHELL.parent]
    return {
        **os.environ,
        "PATH": os.pathsep.join(str(d) for d in dossiers),
        "LOCALAPPDATA": str(local),
    }


def lancer_powershell(
    tmp_path: Path,
    script: Path,
    *arguments: str,
    entree: bytes = b"",
    chemin: tuple[Path, ...] = (),
) -> subprocess.CompletedProcess:
    assert POWERSHELL.is_file(), (
        f"powershell.exe introuvable ({POWERSHELL}) :"
        " les tests du lanceur ne peuvent pas s'exécuter"
    )
    commande = [
        str(POWERSHELL),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        *arguments,
    ]
    return subprocess.run(
        commande,
        input=entree,
        capture_output=True,
        cwd=tmp_path,
        env=environnement(tmp_path, chemin),
        timeout=120,
    )


def piloter(
    tmp_path: Path,
    *appels: tuple[str, dict],
    culture: str | None = None,
    chemin: tuple[Path, ...] = (),
) -> list[dict]:
    """Appelle des fonctions de lancer.ps1 ; une réponse par appel, dans l'ordre.

    Demande et réponse sont du JSON en ASCII pur : Windows PowerShell 5.1 abîme
    les accents sur ses flux standard.
    """
    demande = {
        "culture": culture,
        "appels": [{"fonction": f, "parametres": p} for f, p in appels],
    }
    resultat = lancer_powershell(
        tmp_path,
        PILOTE,
        entree=json.dumps(demande).encode("ascii"),
        chemin=chemin,
    )
    assert resultat.returncode == 0, (
        f"pilote en échec (code {resultat.returncode}) :"
        f" {resultat.stdout!r} {resultat.stderr!r}"
    )
    assert resultat.stdout.isascii(), resultat.stdout
    reponses = json.loads(resultat.stdout)["resultats"]
    assert len(reponses) == len(appels), reponses
    return reponses


def valeurs(reponses: list[dict]) -> list[object]:
    """Résultats des appels ; une fonction qui a levé une erreur fait échouer."""
    assert [r["erreur"] for r in reponses if "erreur" in r] == []
    return [r.get("resultat") for r in reponses]


def objets(reponses: list[dict]) -> list[dict]:
    """Comme valeurs(), pour des fonctions qui rendent un objet."""
    resultats = valeurs(reponses)
    assert [r for r in resultats if not isinstance(r, dict)] == []
    return resultats


class TestFichierCmd:
    def test_ascii_pur(self):
        # cmd lit le fichier dans la page de code OEM : un accent y serait abîmé.
        assert CMD.is_file()
        assert [octet for octet in CMD.read_bytes() if octet >= 0x80] == []

    def test_aucun_caractere_de_controle(self):
        # Plus strict que le garde des sources, qui tolère la tabulation. Un « \v »
        # interprété par un outil d'écriture donnerait un 0x0B invisible dans le chemin.
        assert CMD.is_file()
        controles = [o for o in CMD.read_bytes() if o < 0x20 and o not in (0x0D, 0x0A)]
        assert controles == []

    def test_fins_de_ligne_crlf_et_3_a_5_lignes(self):
        assert CMD.is_file()
        octets = CMD.read_bytes()

        assert octets.endswith(b"\r\n")
        assert octets.count(b"\n") == octets.count(b"\r\n") == octets.count(b"\r")
        assert 3 <= octets.count(b"\r\n") <= 5

    def test_ne_lance_que_lancer_ps1_a_cote_de_lui(self):
        assert CMD.is_file()
        texte = CMD.read_bytes().decode("ascii")

        fichiers = re.findall(
            r"(?:%~dp0)?([\w.-]+\.(?:ps1|py|cmd|bat|exe|vbs|js))\b", texte
        )
        assert fichiers == ["powershell.exe", "lancer.ps1"]
        assert texte.count("%~") == 1
        assert '-NoProfile -ExecutionPolicy Bypass -File "%~dp0lancer.ps1"' in texte

    def test_pause_apres_le_lancement_et_code_de_sortie_transmis(self):
        assert CMD.is_file()
        lignes = CMD.read_bytes().decode("ascii").split("\r\n")

        assert "pause" in lignes
        lancement = [n for n, ligne in enumerate(lignes) if "lancer.ps1" in ligne]
        assert lancement and lancement[0] < lignes.index("pause")
        # pause remet ERRORLEVEL à 0 : le code est mémorisé avant, rendu après.
        assert lignes[lancement[0] + 1] == 'set "CODE=%ERRORLEVEL%"'
        assert lignes[lignes.index("pause") + 1] == "exit /b %CODE%"

    def test_gitattributes_impose_crlf(self):
        resultat = subprocess.run(
            ["git", "check-attr", "eol", "--", CMD.name],
            cwd=RACINE,
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert resultat.returncode == 0, resultat.stderr
        assert resultat.stdout.strip() == f"{CMD.name}: eol: crlf"


class TestScriptsPowerShell:
    @pytest.mark.parametrize("script", [EXPORT, LANCEUR, PILOTE], ids=lambda s: s.name)
    def test_utf8_avec_bom(self, script):
        # Sans BOM, Windows PowerShell 5.1 lit le script dans la page de code ANSI.
        assert script.is_file()
        assert script.read_bytes().startswith(BOM)

    @avec_powershell
    @pytest.mark.parametrize("script", [EXPORT, LANCEUR, PILOTE], ids=lambda s: s.name)
    def test_syntaxe_valide_pour_powershell_5_1(self, tmp_path, script):
        assert script.is_file()
        verificateur = tmp_path / "syntaxe.ps1"
        verificateur.write_bytes(
            BOM + b"param([string]$Chemin)\r\n"
            b"$erreurs = $null\r\n"
            b"[System.Management.Automation.Language.Parser]::ParseFile("
            b"$Chemin, [ref]$null, [ref]$erreurs) | Out-Null\r\n"
            b"[Console]::Out.Write($erreurs.Count)\r\n"
        )

        resultat = lancer_powershell(tmp_path, verificateur, str(script))

        assert (resultat.returncode, resultat.stdout) == (0, b"0"), resultat.stderr


class TestMoindrePrivilege:
    def test_une_seule_elevation_dans_invoke_exporteleve(self):
        assert LANCEUR.is_file()
        texte = texte_de(LANCEUR)

        assert texte.count("-Verb RunAs") == 1
        debut = texte.find("\nfunction Invoke-ExportEleve {")
        assert debut != -1
        fin = texte.index("\n}\n", debut)
        assert debut < texte.index("-Verb RunAs") < fin

    def test_chemin_de_l_export_depuis_psscriptroot(self):
        assert LANCEUR.is_file()

        assert "Join-Path $PSScriptRoot 'export-4625.ps1'" in texte_de(LANCEUR)

    def test_rien_n_est_interprete_comme_une_commande(self):
        assert LANCEUR.is_file()
        texte = texte_de(LANCEUR).lower()

        for interdit in ("invoke-expression", "iex "):
            assert interdit not in texte
        # Les options -Command et -EncodedCommand ; ni Get-Command ni -CommandType.
        assert re.findall(r"(?<!\w)-(?:encoded)?command\b", texte) == []

    def test_powershell_eleve_designe_par_son_chemin_complet(self):
        # Jamais « powershell.exe » seul : il serait cherché dans le PATH.
        assert LANCEUR.is_file()
        texte = texte_de(LANCEUR)

        assert "[Environment]::GetFolderPath('System')" in texte
        assert "-FilePath (Get-CheminPowerShell)" in texte


@avec_powershell
class TestPilote:
    def test_message_accentue_aller_retour_intact(self, tmp_path):
        message = "Élévation refusée : « journal Sécurité » à l'œil, ça"

        resultat = lancer_powershell(
            tmp_path,
            PILOTE,
            entree=json.dumps(
                {
                    "culture": None,
                    "appels": [
                        {"fonction": "Write-Output", "parametres": {"InputObject": message}}
                    ],
                }
            ).encode("ascii"),
        )

        assert resultat.returncode == 0, resultat.stderr
        assert resultat.stdout.isascii()
        assert b"\\" + b"u00e9" in resultat.stdout  # « é » échappé, pas en octets
        assert json.loads(resultat.stdout) == {"resultats": [{"resultat": message}]}

    def test_erreur_d_une_fonction_rendue_sans_arreter_le_pilote(self, tmp_path):
        reponses = piloter(
            tmp_path,
            ("Fonction-Absente", {}),
            ("Write-Output", {"InputObject": "suite"}),
        )

        assert "erreur" in reponses[0] and "Fonction-Absente" in reponses[0]["erreur"]
        assert reponses[1] == {"resultat": "suite"}

    def test_charger_le_lanceur_ne_declenche_rien(self, tmp_path):
        piloter(tmp_path)

        assert list((tmp_path / "LocalAppData").glob("Ego*")) == []


@avec_powershell
class TestArgumentsDuLanceur:
    # Lus par le lanceur lui-même : refusés par PowerShell, ils donneraient le
    # code 1, que l'appelant prendrait pour « alertes ».
    def test_jours_lu_ou_7_par_defaut(self, tmp_path):
        cas = [[], ["-Jours", "30"], ["-jours", "1"], ["-JOURS", "abc"]]

        resultats = objets(
            piloter(tmp_path, *[("Read-Arguments", {"Arguments": c}) for c in cas])
        )

        assert resultats == [
            {"Jours": jours, "Erreur": None} for jours in ("7", "30", "1", "abc")
        ]

    def test_usage_incorrect_refuse(self, tmp_path):
        cas = [["-Jours"], ["-Jours", "3", "x"], ["-Jorus", "3"], ["30"], ["-Jours", ""]]

        resultats = objets(
            piloter(tmp_path, *[("Read-Arguments", {"Arguments": c}) for c in cas])
        )

        assert [r.get("Jours") for r in resultats] == [None] * len(cas)
        for resultat in resultats:
            assert "Usage : ego-sentinelle.cmd [-Jours N]" in (resultat.get("Erreur") or "")


@avec_powershell
class TestDepuis:
    def test_jours_convertis_en_date_iso_locale(self, tmp_path):
        cas = {"7": "2026-11-03T14:30:05", "1": "2026-11-09T14:30:05",
               "365": "2025-11-10T14:30:05", "007": "2026-11-03T14:30:05"}

        resultats = objets(
            piloter(
                tmp_path,
                *[
                    ("ConvertTo-Depuis", {"Jours": jours, "Maintenant": MAINTENANT})
                    for jours in cas
                ],
                culture=CULTURE_PIEGE,
            )
        )

        assert resultats == [{"Depuis": d, "Erreur": None} for d in cas.values()]
        for depuis in cas.values():  # format accepté par export-4625.ps1
            assert datetime.strptime(depuis, "%Y-%m-%dT%H:%M:%S")

    def test_jours_invalides_refuses(self, tmp_path):
        chiffre_arabe = "\N{ARABIC-INDIC DIGIT SEVEN}"
        refuses = ["0", "-1", "abc", "1.5", " 7", "7 ", "+7", chiffre_arabe, "366",
                   "1000", "", "7; calc", "7\n"]

        resultats = objets(
            piloter(
                tmp_path,
                *[
                    ("ConvertTo-Depuis", {"Jours": jours, "Maintenant": MAINTENANT})
                    for jours in refuses
                ],
            )
        )

        acceptes = [j for j, r in zip(refuses, resultats) if r.get("Depuis") is not None]
        assert acceptes == []
        for resultat in resultats:
            assert "-Jours invalide" in (resultat.get("Erreur") or "")
            assert "de 1 à 365" in resultat["Erreur"]

    def test_valeur_tres_longue_non_recopiee_en_entier(self, tmp_path):
        (resultat,) = objets(
            piloter(
                tmp_path,
                ("ConvertTo-Depuis", {"Jours": "9" * 5000, "Maintenant": MAINTENANT}),
            )
        )

        assert resultat.get("Depuis") is None
        assert 0 < len(resultat.get("Erreur") or "") < 300


@avec_powershell
class TestFichiers:
    def test_noms_horodates_sans_dependre_de_la_culture(self, tmp_path):
        (noms,) = objets(
            piloter(
                tmp_path,
                ("Get-NomsFichiers", {"Maintenant": "2026-01-02T03:04:05"}),
                culture=CULTURE_PIEGE,
            )
        )

        assert noms == {
            "Export": "echecs-20260102-030405.csv",
            "Rapport": "rapport-20260102-030405.html",
        }

    def test_dossier_de_travail_sous_localappdata(self, tmp_path):
        (dossier,) = valeurs(
            piloter(tmp_path, ("Get-DossierTravail", {"LocalAppData": r"C:\Faux\Local"}))
        )

        assert dossier == r"C:\Faux\Local\EgoSentinelle"


@avec_powershell
class TestArgumentsDeLExport:
    def test_argument_entre_guillemets(self, tmp_path):
        cas = {
            r"C:\simple.csv": r'"C:\simple.csv"',
            r"C:\a b\c.csv": r'"C:\a b\c.csv"',
            "": '""',
            # Une barre finale avalerait le guillemet fermant : elle est doublée.
            "C:\\dossier\\": '"C:\\dossier\\\\"',
            "C:\\dossier\\\\": '"C:\\dossier\\\\\\\\"',
            "C:\\a\\b": '"C:\\a\\b"',  # au milieu, les barres restent seules
        }

        resultats = valeurs(
            piloter(
                tmp_path, *[("ConvertTo-ArgumentWindows", {"Texte": t}) for t in cas]
            )
        )

        assert resultats == list(cas.values())

    def test_guillemet_refuse(self, tmp_path):
        # Impossible dans un chemin Windows : sa présence trahit une manipulation.
        (reponse,) = piloter(
            tmp_path, ("ConvertTo-ArgumentWindows", {"Texte": 'a" -Depuis "x'})
        )

        assert "resultat" not in reponse
        assert "guillemet" in reponse.get("erreur", "")

    def test_ligne_de_commande_complete(self, tmp_path):
        script = r"C:\Ego l'essai & (copie)\export-4625.ps1"
        sortie = r"C:\Users\x y\AppData\Local\EgoSentinelle\echecs-20261110-143005.csv"

        (ligne,) = valeurs(
            piloter(
                tmp_path,
                (
                    "Get-ArgumentsExport",
                    {"Script": script, "Sortie": sortie, "Depuis": "2026-11-03T14:30:05"},
                ),
            )
        )

        assert ligne == (
            f'-NoProfile -ExecutionPolicy Bypass -File "{script}"'
            f' -Sortie "{sortie}" -Depuis "2026-11-03T14:30:05"'
        )

    @pytest.mark.parametrize("depuis", ["2026-11-03T14:30:05", "a b\\"], ids=["date", "barre"])
    def test_aller_retour_reel_depuis_un_dossier_piege(self, tmp_path, depuis):
        # Même lancement que l'export élevé, sans -Verb RunAs : powershell.exe
        # découpe la ligne de commande de la même façon, sans fenêtre UAC.
        piege = tmp_path / DOSSIER_PIEGE
        piege.mkdir()
        faux_export = piege / "export-4625.ps1"
        faux_export.write_bytes(
            BOM + b"param([string]$Sortie, [string]$Depuis)\r\n"
            b"Set-Content -LiteralPath $Sortie -Value ($Sortie + '|' + $Depuis)"
            b" -Encoding UTF8\r\n"
            b"exit 3\r\n"
        )
        sortie = piege / "echecs & (1).csv"

        (reponse,) = piloter(
            tmp_path,
            (
                "Invoke-ExportSansElevation",
                {"Script": str(faux_export), "Sortie": str(sortie), "Depuis": depuis},
            ),
        )

        assert reponse == {"resultat": 3}  # le code de l'export est transmis
        assert sortie.is_file()
        assert sortie.read_bytes().decode("utf-8-sig").strip() == f"{sortie}|{depuis}"
        assert sorted(p.name for p in piege.iterdir()) == sorted(
            [faux_export.name, sortie.name]
        )


@avec_powershell
class TestDecisions:
    def test_export_reussi_on_continue(self, tmp_path):
        (decision,) = objets(piloter(tmp_path, ("Get-DecisionExport", {"Code": 0})))

        assert decision.get("Continuer") is True

    def test_export_en_echec_arret_et_message_autonome(self, tmp_path):
        # La fenêtre élevée se ferme aussitôt : son texte est perdu. Chaque
        # message dit donc ce qui s'est passé, les causes et quoi faire.
        attendus = {
            1: ["code 1", "journal Sécurité", "administrateur", "stratégie d'exécution"],
            2: ["code 2", "-Depuis", "lanceur"],
            99: ["code 99"],
            -1073741510: ["code -1073741510"],  # fenêtre fermée avant la fin
        }

        decisions = objets(
            piloter(tmp_path, *[("Get-DecisionExport", {"Code": c}) for c in attendus])
        )

        assert [d.get("Continuer") for d in decisions] == [False] * len(attendus)
        messages = [d.get("Message") or "" for d in decisions]
        for message, fragments in zip(messages, attendus.values()):
            assert [f for f in fragments if f not in message] == []
            assert "export" in message.lower()
            assert "Aucun rapport" in message
            assert "export-4625.ps1" in message  # comment voir le message d'origine
        assert len(set(messages[:3])) == 3

    def test_analyse_rapport_ouvert_pour_0_et_1_seulement(self, tmp_path):
        codes = [0, 1, 2, 130, 99, -1]

        decisions = objets(
            piloter(tmp_path, *[("Get-DecisionAnalyse", {"Code": c}) for c in codes])
        )

        assert [d.get("Ouvrir") for d in decisions] == [True, True, False, False, False, False]
        messages = dict(zip(codes, (d.get("Message") or "" for d in decisions)))
        assert "aucune alerte" in messages[0].lower()
        assert "alerte" in messages[1] and "aucune" not in messages[1].lower()
        assert "erreur" in messages[2] and "pas ouvert" in messages[2]
        assert "interrompue" in messages[130]
        assert "code 99" in messages[99] and "code -1" in messages[-1]


def faux_python(dossier: Path, nom: str, code: int) -> Path:
    """Faux interpréteur : un .cmd qui sort avec le code donné."""
    dossier.mkdir(exist_ok=True)
    (dossier / f"{nom}.cmd").write_bytes(f"@exit /b {code}\r\n".encode("ascii"))
    return dossier


@avec_powershell
class TestPython:
    def test_absent(self, tmp_path):
        assert valeurs(piloter(tmp_path, ("Find-Python", {}))) == [None]

    def test_py_prefere_a_python(self, tmp_path):
        outils = faux_python(tmp_path / "outils", "py", 0)
        faux_python(outils, "python", 0)

        (trouve,) = objets(piloter(tmp_path, ("Find-Python", {}), chemin=(outils,)))

        assert trouve == {"Commande": str(outils / "py.cmd"), "Arguments": ["-3"]}

    def test_python_a_defaut_de_py(self, tmp_path):
        outils = faux_python(tmp_path / "outils", "python", 0)

        (trouve,) = objets(piloter(tmp_path, ("Find-Python", {}), chemin=(outils,)))

        assert trouve == {"Commande": str(outils / "python.cmd"), "Arguments": []}

    def test_python_trop_ancien_ou_alias_du_store_ecarte(self, tmp_path):
        # L'alias « python » du Microsoft Store existe mais sort en erreur.
        outils = faux_python(tmp_path / "outils", "py", 1)
        faux_python(outils, "python", 9009)

        assert valeurs(piloter(tmp_path, ("Find-Python", {}), chemin=(outils,))) == [None]


@avec_powershell
class TestAnalyse:
    def test_chemins_pieges_transmis_intacts_a_python(self, tmp_path):
        # Le vrai sentinelle.py, sur un export fictif, depuis un dossier piège.
        piege = tmp_path / DOSSIER_PIEGE
        piege.mkdir()
        csv = piege / "echecs & (1).csv"
        csv.write_bytes((RACINE / "tests" / "donnees" / "export_attaque.csv").read_bytes())
        rapport = piege / "rapport (1) l'essai.html"

        (code,) = valeurs(
            piloter(
                tmp_path,
                (
                    "Invoke-AnalyseSansConsole",
                    {
                        "Python": {"Commande": sys.executable, "Arguments": []},
                        "Sentinelle": str(RACINE / "sentinelle.py"),
                        "Csv": str(csv),
                        "Rapport": str(rapport),
                    },
                ),
            )
        )

        assert code == 1  # l'export d'attaque contient des alertes
        assert rapport.is_file()
        document = rapport.read_bytes().decode("utf-8")
        assert '<body class="etat-alerte">' in document
        assert "echecs &amp; (1).csv" in document
        assert sorted(p.name for p in piege.iterdir()) == sorted([csv.name, rapport.name])


@avec_powershell
class TestDeroule:
    """Le vrai lancer.ps1, arrêté avant l'élévation (PATH sans Python)."""

    @pytest.mark.parametrize("jours", ["0", "abc", "366"])
    def test_jours_invalide_code_2_sans_rien_creer(self, tmp_path, jours):
        resultat = lancer_powershell(tmp_path, LANCEUR, "-Jours", jours)

        assert resultat.returncode == 2, resultat.stdout + resultat.stderr
        assert b"-Jours invalide" in resultat.stdout + resultat.stderr
        assert list((tmp_path / "LocalAppData").glob("Ego*")) == []

    @pytest.mark.parametrize(
        "arguments", [["-Jours"], ["-Jours", "7", "surplus"], ["-Jorus", "7"]]
    )
    def test_usage_incorrect_code_2_sans_rien_creer(self, tmp_path, arguments):
        resultat = lancer_powershell(tmp_path, LANCEUR, *arguments)

        assert resultat.returncode == 2, resultat.stdout + resultat.stderr
        assert b"Usage : ego-sentinelle.cmd [-Jours N]" in resultat.stdout + resultat.stderr
        assert list((tmp_path / "LocalAppData").glob("Ego*")) == []

    @pytest.mark.parametrize(
        ("arguments", "attendu"),
        [("-Jours 0", b"-Jours invalide"), ("", b"export-4625.ps1")],
        ids=["jours-invalide", "depot-incomplet"],
    )
    def test_cmd_lance_depuis_un_dossier_piege(self, tmp_path, arguments, attendu):
        # Le vrai .cmd, copié avec lancer.ps1 seul dans un dossier au nom piégé et
        # lancé depuis un autre dossier : il doit trouver lancer.ps1 à côté de lui.
        # Sans export-4625.ps1, le lanceur s'arrête avant Python et avant l'UAC.
        # Pas de « % » ici : cmd /c le développerait avant même de lire le fichier.
        piege = tmp_path / "Ego l'essai & (copie) é ^"
        piege.mkdir()
        for fichier in (CMD, LANCEUR):
            (piege / fichier.name).write_bytes(fichier.read_bytes())

        resultat = subprocess.run(
            # /s et guillemets extérieurs : la forme qu'emploie l'Explorateur.
            f'cmd.exe /d /s /c ""{piege / CMD.name}" {arguments}"',
            stdin=subprocess.DEVNULL,  # « pause » rend la main aussitôt
            capture_output=True,
            cwd=tmp_path,
            env=environnement(tmp_path),
            timeout=120,
        )

        sorties = resultat.stdout + resultat.stderr
        assert resultat.returncode == 2, sorties  # transmis malgré « pause »
        assert attendu in sorties
        assert list((tmp_path / "LocalAppData").glob("Ego*")) == []

    def test_python_absent_code_2_avant_tout_export(self, tmp_path):
        resultat = lancer_powershell(tmp_path, LANCEUR)

        assert resultat.returncode == 2, resultat.stdout + resultat.stderr
        assert b"Python" in resultat.stdout + resultat.stderr
        travail = tmp_path / "LocalAppData" / "EgoSentinelle"
        assert travail.is_dir()  # étape 1 faite, arrêt à l'étape 2
        assert list(travail.iterdir()) == []
