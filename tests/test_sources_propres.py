"""Test de garde : aucun caractère invisible ou de contrôle dans les sources.

Un caractère bidirectionnel (U+202E…) ou invisible peut faire lire au relecteur
autre chose que ce que Python exécute (attaque « Trojan Source »). Les tests qui
en ont besoin les écrivent en échappement : "\\u202e" ou "\\N{...}".
"""

import subprocess
import unicodedata
from collections.abc import Iterable
from pathlib import Path

import pytest

from ego.neutralisation import CATEGORIES_NEUTRALISEES

RACINE = Path(__file__).parent.parent
EXTENSIONS = frozenset({".py", ".json", ".md", ".ps1", ".toml", ".cfg"})
# Les catégories invisibles neutralisées dans le rapport : Cc, Cf, Co, Cs. Les
# espaces et séparateurs (Zs, Zl, Zp) restent permis : le français typographié
# emploie des espaces insécables.
CATEGORIES_INTERDITES = frozenset(c for c in CATEGORIES_NEUTRALISEES if c[0] == "C")
CONTROLES_PERMIS = frozenset("\n\r\t")
BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"
# Windows PowerShell 5.1 lit un script sans BOM dans la page de code ANSI : le
# BOM est permis, en tête de fichier seulement, pour ces extensions.
EXTENSIONS_AVEC_BOM = frozenset({".ps1"})
DOSSIER_DONNEES = "tests/donnees/"

# Fichiers de tests/donnees/ qui DOIVENT contenir de vrais caractères piégés,
# nommés un par un (jamais un dossier ni un motif). Chaque entrée doit exister et
# contenir au moins un caractère interdit, sinon test_liste_blanche_du_depot
# échoue. Vide pour l'instant : aucun fichier de données n'en a besoin.
LISTE_BLANCHE: frozenset[str] = frozenset()


def fichiers_surveilles(racine: Path) -> list[str]:
    """Fichiers suivis par git, ou nouveaux et non ignorés, aux extensions voulues.

    --others : un fichier pas encore commité est vérifié avant son premier commit.
    """
    sortie = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=racine,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8")
    noms = {nom for nom in sortie.split("\0") if nom}
    return sorted(nom for nom in noms if Path(nom).suffix in EXTENSIONS)


def caracteres_interdits(texte: str, bom_autorise: bool = False) -> list[str]:
    """Positions « ligne:colonne U+XXXX », comptées en caractères à partir de 1.

    Les lignes sont coupées sur LF seulement : U+2028 ou un CR isolé ne les
    décalent pas.
    """
    trouves = []
    for numero, ligne in enumerate(texte.split("\n"), start=1):
        for colonne, caractere in enumerate(ligne, start=1):
            if bom_autorise and (numero, colonne, caractere) == (1, 1, BOM):
                continue
            if _est_interdit(caractere):
                trouves.append(f"{numero}:{colonne} U+{ord(caractere):04X}")
    return trouves


def _est_interdit(caractere: str) -> bool:
    return (
        caractere not in CONTROLES_PERMIS
        and unicodedata.category(caractere) in CATEGORIES_INTERDITES
    )


def anomalies(
    racine: Path, chemins: Iterable[str], liste_blanche: frozenset[str] = LISTE_BLANCHE
) -> list[str]:
    """« chemin:ligne:colonne U+XXXX » pour chaque caractère interdit.

    Un octet non UTF-8 apparaît comme un demi-codet U+DC80 à U+DCFF
    (surrogateescape) : signalé, sans faire planter le garde.
    """
    trouves = []
    for nom in chemins:
        chemin = racine / nom
        if nom in liste_blanche or not chemin.is_file():
            continue
        texte = chemin.read_bytes().decode("utf-8", "surrogateescape")
        positions = caracteres_interdits(
            texte, bom_autorise=chemin.suffix in EXTENSIONS_AVEC_BOM
        )
        trouves += [f"{nom}:{position}" for position in positions]
    return trouves


def entrees_douteuses(racine: Path, liste_blanche: frozenset[str]) -> list[str]:
    """Entrées hors de tests/donnees/, absentes, ou sans caractère piégé."""
    douteuses = []
    for nom in sorted(liste_blanche):
        chemin = racine / nom
        if not nom.startswith(DOSSIER_DONNEES):
            douteuses.append(f"{nom} : hors de {DOSSIER_DONNEES}")
        elif not chemin.is_file():
            douteuses.append(f"{nom} : introuvable")
        elif not anomalies(racine, [nom], liste_blanche=frozenset()):
            douteuses.append(f"{nom} : aucun caractère piégé, à retirer")
    return douteuses


RLO = "\N{RIGHT-TO-LEFT OVERRIDE}"


class TestRegle:
    def test_bidi_detecte_avec_ligne_et_colonne(self):
        assert caracteres_interdits(f"ab\ncd{RLO}ef") == ["2:3 U+202E"]

    def test_plusieurs_occurrences_toutes_signalees(self):
        texte = f"{RLO}a{RLO}\n\x1b"

        assert caracteres_interdits(texte) == ["1:1 U+202E", "1:3 U+202E", "2:1 U+001B"]

    @pytest.mark.parametrize(
        ("caractere", "point"),
        [
            ("\N{LEFT-TO-RIGHT ISOLATE}", "U+2066"),  # Cf
            ("\N{RIGHT-TO-LEFT MARK}", "U+200F"),  # Cf
            ("\N{ZERO WIDTH SPACE}", "U+200B"),  # Cf
            ("\N{ARABIC LETTER MARK}", "U+061C"),  # Cf
            ("\N{ZERO WIDTH NO-BREAK SPACE}", "U+FEFF"),  # Cf : BOM hors début
            ("\N{LANGUAGE TAG}", "U+E0001"),  # Cf hors du plan de base
            ("\x00", "U+0000"),  # Cc
            ("\x1b", "U+001B"),  # Cc : ESC
            ("\x7f", "U+007F"),  # Cc : DEL
            ("\x85", "U+0085"),  # Cc : NEL (C1)
            ("\x0b", "U+000B"),  # Cc : tabulation verticale
            ("\x0c", "U+000C"),  # Cc : saut de page
            (chr(0xE000), "U+E000"),  # Co : usage privé
            (chr(0xD800), "U+D800"),  # Cs : demi-codet
        ],
    )
    def test_categories_interdites(self, caractere, point):
        assert caracteres_interdits(f"a{caractere}b") == [f"1:2 {point}"]

    @pytest.mark.parametrize(
        "texte",
        [
            "a\nb\r\nc\td",
            "Entête, garçon, « guillemets », 😀.",
            "«\N{NO-BREAK SPACE}texte\N{NARROW NO-BREAK SPACE}»",  # Zs : hors périmètre
            "",
        ],
        ids=["blancs-ordinaires", "accents-emoji", "espaces-insecables", "vide"],
    )
    def test_textes_acceptes(self, texte):
        assert caracteres_interdits(texte) == []

    def test_lignes_comptees_sur_lf_seulement(self):
        # splitlines() couperait aussi sur U+2028 et décalerait les lignes.
        texte = f"a\N{LINE SEPARATOR}b\x1c\nc{RLO}"

        assert caracteres_interdits(texte) == ["1:4 U+001C", "2:2 U+202E"]

    def test_colonne_apres_crlf(self):
        assert caracteres_interdits(f"a\r\nb{RLO}") == ["2:2 U+202E"]

    def test_colonne_en_caracteres_et_non_en_octets(self):
        assert caracteres_interdits(f"é😀{RLO}") == ["1:3 U+202E"]

    def test_bom_refuse_par_defaut(self):
        assert caracteres_interdits("\N{ZERO WIDTH NO-BREAK SPACE}x") == ["1:1 U+FEFF"]

    def test_bom_autorise_seulement_en_tete(self):
        bom = "\N{ZERO WIDTH NO-BREAK SPACE}"

        assert caracteres_interdits(f"{bom}x", bom_autorise=True) == []
        assert caracteres_interdits(f"x{bom}", bom_autorise=True) == ["1:2 U+FEFF"]
        assert caracteres_interdits(f"{bom}{bom}", bom_autorise=True) == ["1:2 U+FEFF"]


class TestFichiers:
    def test_fichier_piege_detecte(self, tmp_path):
        # Démonstration : un fichier temporaire contenant U+202E fait échouer le garde.
        (tmp_path / "piege.py").write_text(f'x = "a{RLO}b"\n', encoding="utf-8")

        assert anomalies(tmp_path, ["piege.py"]) == ["piege.py:1:7 U+202E"]

    def test_chemin_relatif_avec_barres_obliques(self, tmp_path):
        (tmp_path / "tests" / "donnees").mkdir(parents=True)
        (tmp_path / "tests" / "donnees" / "m.json").write_text(
            f'{{"a": "\n{RLO}"}}', encoding="utf-8"
        )

        assert anomalies(tmp_path, ["tests/donnees/m.json"]) == [
            "tests/donnees/m.json:2:1 U+202E"
        ]

    def test_octet_non_utf8_signale_sans_plantage(self, tmp_path):
        # surrogateescape : l'octet 0xE9 devient le demi-codet U+DCE9.
        (tmp_path / "f.md").write_bytes(b"ok\n\xe9t\xe9\n")

        assert anomalies(tmp_path, ["f.md"]) == ["f.md:2:1 U+DCE9", "f.md:2:3 U+DCE9"]

    def test_bom_accepte_en_tete_de_script_powershell(self, tmp_path):
        # Windows PowerShell 5.1 lit un script sans BOM dans la page de code ANSI.
        (tmp_path / "s.ps1").write_bytes(b"\xef\xbb\xbfWrite-Host '\xc3\xa9'\r\n")

        assert anomalies(tmp_path, ["s.ps1"]) == []

    def test_bom_refuse_ailleurs(self, tmp_path):
        (tmp_path / "s.py").write_bytes(b"\xef\xbb\xbfx = 1\n")

        assert anomalies(tmp_path, ["s.py"]) == ["s.py:1:1 U+FEFF"]

    def test_fichier_supprime_du_disque_ignore(self, tmp_path):
        # git ls-files liste encore un fichier suivi supprimé mais non indexé.
        assert anomalies(tmp_path, ["absent.py"]) == []

    def test_liste_blanche_nommee_et_non_par_dossier(self, tmp_path):
        donnees = tmp_path / "tests" / "donnees"
        donnees.mkdir(parents=True)
        for nom in ("piege.json", "autre.json"):
            (donnees / nom).write_text(f'["{RLO}"]', encoding="utf-8")
        chemins = ["tests/donnees/piege.json", "tests/donnees/autre.json"]

        trouves = anomalies(
            tmp_path, chemins, liste_blanche=frozenset({"tests/donnees/piege.json"})
        )

        assert trouves == ["tests/donnees/autre.json:1:3 U+202E"]


class TestListeBlanche:
    def test_entrees_douteuses_signalees(self, tmp_path):
        donnees = tmp_path / "tests" / "donnees"
        donnees.mkdir(parents=True)
        (donnees / "piege.json").write_text(f'["{RLO}"]', encoding="utf-8")
        (donnees / "propre.json").write_text("[]", encoding="utf-8")
        (tmp_path / "ego.py").write_text(f"# {RLO}", encoding="utf-8")
        liste = frozenset(
            {
                "tests/donnees/piege.json",
                "tests/donnees/propre.json",
                "tests/donnees/absent.json",
                "tests/donnees/",
                "ego.py",
            }
        )

        assert entrees_douteuses(tmp_path, liste) == [
            "ego.py : hors de tests/donnees/",
            "tests/donnees/ : introuvable",
            "tests/donnees/absent.json : introuvable",
            "tests/donnees/propre.json : aucun caractère piégé, à retirer",
        ]

    def test_liste_blanche_du_depot(self):
        assert entrees_douteuses(RACINE, LISTE_BLANCHE) == []


class TestDepot:
    def test_fichiers_surveilles(self):
        noms = fichiers_surveilles(RACINE)

        attendus = {
            "README.md",
            "ego/neutralisation.py",
            "export-4625.ps1",
            "modeles/ego.json",
            "pyproject.toml",
            "tests/test_sources_propres.py",
        }
        assert attendus <= set(noms)
        assert {Path(nom).suffix for nom in noms} <= EXTENSIONS

    def test_aucun_caractere_invisible(self):
        trouves = anomalies(RACINE, fichiers_surveilles(RACINE))

        assert trouves == [], "\n".join(trouves)
