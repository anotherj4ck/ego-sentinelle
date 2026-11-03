import pytest

from ego.neutralisation import neutraliser


class TestCaracteresDeControle:
    def test_sequence_ansi_rendue_visible_et_inerte(self):
        assert neutraliser("\x1b[31mroot\x1b[0m") == "\\x1b[31mroot\\x1b[0m"

    @pytest.mark.parametrize(
        ("caractere", "attendu"),
        [
            ("\r", "\\x0d"),
            ("\n", "\\x0a"),
            ("\t", "\\x09"),
            ("\x00", "\\x00"),
            ("\x7f", "\\x7f"),  # DEL
            ("\x9b", "\\x9b"),  # CSI sur 8 bits (C1)
        ],
        ids=["CR", "LF", "TAB", "NUL", "DEL", "CSI-C1"],
    )
    def test_controles_c0_et_c1_neutralises(self, caractere, attendu):
        assert neutraliser(f"a{caractere}b") == f"a{attendu}b"


class TestUnicodeInvisible:
    @pytest.mark.parametrize(
        ("caractere", "attendu"),
        [
            ("‮", "\\u202e"),  # RLO : inverse l'affichage
            ("‪", "\\u202a"),  # LRE
            ("‬", "\\u202c"),  # PDF
            ("⁦", "\\u2066"),  # LRI
            ("⁩", "\\u2069"),  # PDI
            ("‏", "\\u200f"),  # RLM
            ("؜", "\\u061c"),  # ALM
            ("​", "\\u200b"),  # espace sans chasse
            (" ", "\\u2028"),  # séparateur de ligne
            (" ", "\\u2029"),  # séparateur de paragraphe
            ("\ud800", "\\ud800"),  # demi-codet isolé
        ],
        ids=["RLO", "LRE", "PDF", "LRI", "PDI", "RLM", "ALM", "ZWSP", "LS", "PS",
             "surrogate"],
    )
    def test_controles_bidirectionnels_et_separateurs_neutralises(
        self, caractere, attendu
    ):
        assert neutraliser(f"a{caractere}b") == f"a{attendu}b"


class TestCaracteresTrompeurs:
    @pytest.mark.parametrize(
        ("caractere", "attendu"),
        [
            ("", "\\ue000"),  # usage privé (Co)
            (" ", "\\xa0"),  # espace insécable (Zs)
            (" ", "\\u2003"),  # espace cadratin (Zs)
            (" ", "\\u202f"),  # espace fine insécable (Zs)
            ("　", "\\u3000"),  # espace idéographique (Zs)
            ("ㅤ", "\\u3164"),  # remplissage Hangul : lettre invisible
            ("ᅟ", "\\u115f"),  # remplissage initial Hangul
            ("⠀", "\\u2800"),  # braille vide
            ("�", "\\ufffd"),  # caractère de remplacement
        ],
        ids=["Co", "NBSP", "EMSP", "NNBSP", "IDSP", "HF", "HCF", "braille", "FFFD"],
    )
    def test_blancs_et_caracteres_trompeurs_neutralises(self, caractere, attendu):
        assert neutraliser(f"a{caractere}b") == f"a{attendu}b"

    def test_compte_d_apparence_vide_rendu_visible(self):
        assert neutraliser("ㅤㅤ") == "\\u3164\\u3164"


class TestTexteOrdinaire:
    @pytest.mark.parametrize(
        "texte",
        ["", "administrateur", "Hélène-Æsa_02", "用户", "admin 2"],
    )
    def test_texte_imprimable_inchange(self, texte):
        assert neutraliser(texte) == texte


class TestBarreObliqueInverse:
    def test_barre_oblique_doublee(self):
        assert neutraliser("DOMAINE\\bob") == "DOMAINE\\\\bob"

    def test_texte_litteral_distinct_d_un_esc_neutralise(self):
        # Sans doublement, le texte « \x1b » et un vrai ESC donneraient le même
        # affichage : un attaquant pourrait simuler une neutralisation.
        assert neutraliser("\\x1b") != neutraliser("\x1b")
