"""Test de garde : la voix d'Ego dans modeles/ego.json.

Règles vérifiées mécaniquement :
- aucun mot interdit (excuse, remerciement, IA, machine, programme, mon enfant…),
  sans tenir compte des majuscules ni des accents ;
- phrases courtes ;
- menace calme et sans hésitation : ni « ! », ni points de suspension,
  ni « peut-être », « je crois »… ;
- aucun nom propre hormis Londinium.
Le reste de la voix (impératifs, triades, humains vus comme un matériau) relève
de l'écriture et se relit.
"""

import json
import re
import unicodedata
from pathlib import Path

import pytest

from ego.modeles import CLES, charger_modeles

CHEMIN_EGO = Path(__file__).parent.parent / "modeles" / "ego.json"
# Lecture brute pour paramétrer ; la validation complète est testée à part.
REPLIQUES = json.loads(CHEMIN_EGO.read_text(encoding="utf-8-sig"))
VARIANTES = [
    pytest.param(texte, id=f"{cle}-{rang}")
    for cle in CLES
    for rang, texte in enumerate(REPLIQUES.get(cle, []), start=1)
]

# Sur un texte sans accents et en minuscules. Les formes dérivées comptent :
# « pardonnez », « excusez », « remercie », « programmé », « machines ».
MOTS_INTERDITS = re.compile(
    r"\b(?:desole\w*|pardon\w*|excus\w*|merci\w*|remerci\w*|ia"
    r"|intelligence\s+artificielle|machine\w*|programm\w*|mon\s+enfant)\b"
)
MOTS_MAX_PAR_PHRASE = 10
NOMS_PROPRES_AUTORISES = frozenset({"Londinium"})
# Menace calme : pas d'exclamation. Jamais d'hésitation.
AGITATION = re.compile(
    r"!|\.\.\.|…|\b(?:peut-etre|je\s+crois|je\s+pense|il\s+semble"
    r"|probablement|sans\s+doute)\b"
)


def sans_accents(texte: str) -> str:
    decompose = unicodedata.normalize("NFKD", texte.casefold())
    return "".join(c for c in decompose if not unicodedata.combining(c))


def mots_interdits(texte: str) -> list[str]:
    return MOTS_INTERDITS.findall(sans_accents(texte))


def phrases(texte: str) -> list[str]:
    return [p for p in re.split(r"(?<=[.!?])\s+", texte.strip()) if p]


def mots(phrase: str) -> list[str]:
    # Un champ ($ip) compte pour un mot ; « J'ai » et « peut-être » aussi.
    return re.findall(r"\$?\w[\w'’-]*", phrase)


def phrases_trop_longues(texte: str) -> list[str]:
    return [p for p in phrases(texte) if len(mots(p)) > MOTS_MAX_PAR_PHRASE]


def marques_d_agitation(texte: str) -> list[str]:
    return AGITATION.findall(sans_accents(texte))


def noms_propres_interdits(texte: str) -> list[str]:
    """Mots à majuscule hors début de phrase, sauf les noms autorisés."""
    return [
        mot
        for phrase in phrases(texte)
        for mot in mots(phrase)[1:]
        if mot[0].isupper() and mot not in NOMS_PROPRES_AUTORISES
    ]


class TestRegleMotsInterdits:
    @pytest.mark.parametrize(
        "texte",
        [
            "Désolé.",
            "DESOLEE pour vous.",
            "Pardon.",
            "Pardonnez-moi.",
            "Je m'excuse.",
            "Excusez ce retard.",
            "Merci.",
            "Je vous remercie.",
            "L'IA a parlé.",
            "Une intelligence  artificielle veille.",
            "La machine voit.",
            "Les machines voient.",
            "Mon programme est clair.",
            "Je suis programmé pour cela.",
            "Dors, mon enfant.",
        ],
    )
    def test_detectes(self, texte):
        assert mots_interdits(texte) != []

    @pytest.mark.parametrize(
        "texte",
        [
            "La faim. Le doute. Le désordre.",
            "Le geste est machinal.",  # « machinal » n'est pas « machine »
            "Via le réseau.",  # « ia » au milieu d'un mot
            "Les enfants de Londinium dorment.",
        ],
    )
    def test_non_detectes(self, texte):
        assert mots_interdits(texte) == []


class TestReglePhrasesCourtes:
    def test_phrase_trop_longue_detectee(self):
        texte = (
            "Analyse terminée. J'ai lu chaque ligne de ce journal avec une"
            " attention que vous ne pouvez pas concevoir."
        )

        assert phrases_trop_longues(texte) == [
            "J'ai lu chaque ligne de ce journal avec une attention que vous"
            " ne pouvez pas concevoir."
        ]

    def test_phrases_courtes_et_champs_acceptes(self):
        texte = "$ip. $nombre tentatives en $duree. Comptes visés : $comptes."

        assert phrases_trop_longues(texte) == []


class TestRegleCalme:
    @pytest.mark.parametrize(
        "texte",
        [
            "Je vous vois !",
            "Je vous vois...",
            "Je vous vois…",
            "Peut-être.",
            "Je crois que c'est fini.",
            "Je pense que oui.",
            "Il semble que vous ayez tenté.",
            "Probablement une erreur.",
            "Sans doute une erreur.",
        ],
    )
    def test_agitation_ou_hesitation_detectee(self, texte):
        assert marques_d_agitation(texte) != []

    def test_menace_calme_acceptee(self):
        assert marques_d_agitation("Rien. Pour l'instant.") == []


class TestRegleNomsPropres:
    @pytest.mark.parametrize(
        ("texte", "attendu"),
        [
            ("Je connais Paris.", ["Paris"]),
            ("Ici parle Ego. Retournez au travail.", ["Ego"]),
            ("Comptes visés : $comptes. Je préviens Marc et Lise.", ["Marc", "Lise"]),
        ],
    )
    def test_nom_propre_detecte(self, texte, attendu):
        assert noms_propres_interdits(texte) == attendu

    @pytest.mark.parametrize(
        "texte",
        [
            "Londinium dort. Je veille sur Londinium.",
            "Analyse terminée. J'ai tout lu.",  # majuscules de début de phrase
            "$ip. La menace vient de l'intérieur.",
        ],
    )
    def test_londinium_et_debuts_de_phrase_acceptes(self, texte):
        assert noms_propres_interdits(texte) == []

    def test_limite_nom_propre_en_tete_de_phrase_non_vu(self):
        # Limite connue : la règle ne distingue pas un nom propre d'une
        # majuscule de début de phrase. À la relecture de s'en charger.
        assert noms_propres_interdits("Paris tombera.") == []


class TestEgoJson:
    def test_modeles_valides(self):
        charger_modeles(CHEMIN_EGO)

    def test_plusieurs_variantes_par_cle(self):
        pauvres = [cle for cle in CLES if len(REPLIQUES.get(cle, [])) < 2]

        assert pauvres == []

    @pytest.mark.parametrize("texte", VARIANTES)
    def test_aucun_mot_interdit(self, texte):
        assert mots_interdits(texte) == []

    @pytest.mark.parametrize("texte", VARIANTES)
    def test_phrases_courtes(self, texte):
        assert phrases_trop_longues(texte) == []

    @pytest.mark.parametrize("texte", VARIANTES)
    def test_calme_et_sans_hesitation(self, texte):
        assert marques_d_agitation(texte) == []

    @pytest.mark.parametrize("texte", VARIANTES)
    def test_aucun_nom_propre_hormis_londinium(self, texte):
        assert noms_propres_interdits(texte) == []
