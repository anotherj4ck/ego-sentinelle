"""Neutralisation des textes contrôlés par l'attaquant, avant tout affichage."""

import unicodedata

# Cc : contrôles C0 et C1 (ESC, CR, LF, TAB, NUL, DEL, CSI 0x9b…).
# Cf : caractères de format invisibles, dont tous les contrôles bidirectionnels
#      (U+202A-U+202E, U+2066-U+2069, U+200E, U+200F, U+061C).
# Cs : demi-codets isolés, que l'encodage de sortie refuserait.
# Zl, Zp : séparateurs de ligne et de paragraphe (U+2028, U+2029).
CATEGORIES_NEUTRALISEES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def neutraliser(texte: str) -> str:
    """Remplace chaque caractère dangereux par son code visible (\\x1b, \\u202e…).

    Le texte reste lisible, mais ne peut plus piloter le terminal ni
    réordonner ou découper l'affichage.
    """
    return "".join(_neutraliser_caractere(c) for c in texte)


def _neutraliser_caractere(caractere: str) -> str:
    if unicodedata.category(caractere) not in CATEGORIES_NEUTRALISEES:
        return caractere
    point = ord(caractere)
    return f"\\x{point:02x}" if point <= 0xFF else f"\\u{point:04x}"
