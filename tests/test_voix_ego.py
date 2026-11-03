"""Test de garde : la voix d'Ego dans modeles/ego.json.

Règles vérifiées mécaniquement :
- aucune formule interdite (pardon, désolé, je m'excuse, merci…) ni IA, machine,
  programme, mon enfant ; sans tenir compte des majuscules ni des accents ;
- phrases courtes ;
- menace calme et sans hésitation : ni « ! », ni « peut-être », « je crois »… ;
  les points de suspension, tic d'Ego, sont autorisés ;
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

# Sur un texte sans accents et en minuscules. Formules d'excuse ou de
# remerciement, et non racines : « Je ne pardonne pas », « sans merci » et
# « Mercier » passent. Ego ne se dit ni IA, ni machine, ni programme.
MOTS_INTERDITS = re.compile(
    r"\b(?:pardon|pardonnez-moi|desolee?s?|je\s+m['’]excuse|excusez-moi"
    r"|(?<!sans\s)merci|ia|intelligence\s+artificielle|machine\w*|programm\w*"
    r"|mon\s+enfant)\b"
)
MOTS_MAX_PAR_PHRASE = 10
NOMS_PROPRES_AUTORISES = frozenset({"Londinium"})
ELISION = re.compile(r"^\w+['’]")  # l', d', qu', jusqu'…
# Menace calme : pas d'exclamation. Jamais d'hésitation. Les points de
# suspension, tic d'Ego, sont autorisés.
AGITATION = re.compile(
    r"!|\b(?:peut-etre|je\s+crois|je\s+pense|il\s+semble"
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
    """Mots à majuscule hors début de phrase, sauf les noms autorisés.

    L'élision est retirée d'abord : « l'Ego » est jugé sur « Ego ».
    """
    return [
        nom
        for phrase in phrases(texte)
        for nom in (ELISION.sub("", mot) for mot in mots(phrase)[1:])
        if nom[:1].isupper() and nom not in NOMS_PROPRES_AUTORISES
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
            "Je m’excuse.",  # apostrophe typographique
            "Excusez-moi.",
            "Merci.",
            "Merci pour votre patience.",
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
            "Je ne pardonne pas.",  # formules, pas racines
            "Une guerre sans merci.",
            "Mercier attend.",
            "Sans merci.",
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
            "Je vous vois!",
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

    @pytest.mark.parametrize(
        "texte",
        [
            "Rien. Pour l'instant.",
            "Je vous vois...",
            "Je vous vois…",
            "Rien… encore.",
        ],
        ids=["calme", "trois-points", "points-de-suspension", "suspension-interne"],
    )
    def test_menace_calme_acceptee(self, texte):
        # Les points de suspension sont un tic d'Ego : autorisés.
        assert marques_d_agitation(texte) == []


class TestRegleNomsPropres:
    @pytest.mark.parametrize(
        ("texte", "attendu"),
        [
            ("Je connais Paris.", ["Paris"]),
            ("Ici parle Ego. Retournez au travail.", ["Ego"]),
            ("Comptes visés : $comptes. Je préviens Marc et Lise.", ["Marc", "Lise"]),
            ("Je vois l'Ego.", ["Ego"]),  # élision
            ("La voix d’Ego.", ["Ego"]),  # apostrophe typographique
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
            "Le silence. L'ordre. L'attente.",  # élision en début de phrase
            "Je garde l'adresse d'aujourd'hui.",
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
