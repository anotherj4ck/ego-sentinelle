"""Neutralisation des textes contrôlés par l'attaquant, avant tout affichage."""

import unicodedata

# Cc : contrôles C0 et C1 (ESC, CR, LF, TAB, NUL, DEL, CSI 0x9b…).
# Cf : caractères de format invisibles, dont tous les contrôles bidirectionnels
#      (U+202A-U+202E, U+2066-U+2069, U+200E, U+200F, U+061C).
# Cs : demi-codets isolés, que l'encodage de sortie refuserait.
# Co : usage privé, sans glyphe convenu.
# Zs : espaces, sauf l'espace ordinaire (insécables, cadratins…, trompeurs).
# Zl, Zp : séparateurs de ligne et de paragraphe (U+2028, U+2029).
CATEGORIES_NEUTRALISEES = frozenset({"Cc", "Cf", "Co", "Cs", "Zs", "Zl", "Zp"})
ESPACE_ORDINAIRE = " "
BARRE_OBLIQUE_INVERSE = "\\"
# Lettres ou symboles qui s'affichent comme un blanc : un compte qui n'en
# contient que paraîtrait vide.
CARACTERES_INVISIBLES = frozenset({"ㅤ", "ᅟ", "⠀", "�"})


def neutraliser(texte: str) -> str:
    """Remplace chaque caractère dangereux par son code visible (\\x1b, \\u202e…).

    Le texte reste lisible, mais ne peut plus piloter le terminal ni
    réordonner ou découper l'affichage.
    """
    return "".join(_neutraliser_caractere(c) for c in texte)


def _est_dangereux(caractere: str) -> bool:
    if caractere == ESPACE_ORDINAIRE:
        return False
    return (
        caractere in CARACTERES_INVISIBLES
        or unicodedata.category(caractere) in CATEGORIES_NEUTRALISEES
    )


def _neutraliser_caractere(caractere: str) -> str:
    # Doubler la barre oblique rend l'échappement non ambigu : le texte
    # « \x1b » devient « \\x1b », un vrai ESC devient « \x1b ».
    if caractere == BARRE_OBLIQUE_INVERSE:
        return BARRE_OBLIQUE_INVERSE * 2
    if not _est_dangereux(caractere):
        return caractere
    point = ord(caractere)
    if point <= 0xFF:
        return f"\\x{point:02x}"
    if point <= 0xFFFF:
        return f"\\u{point:04x}"
    # Hors du plan de base : 8 chiffres, sinon « \ue0001 » se lirait
    # « \ue000 » suivi de « 1 ».
    return f"\\U{point:08x}"
