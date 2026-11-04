import json

import pytest

from ego.modeles import ErreurModeles, Modeles, charger_modeles

VALIDES = {
    "entete": ["Entête $seuil $fenetre."],
    "alerte": ["$ip $nombre $duree $comptes $seuil $fenetre $total $debut $fin.", "B"],
    "alerte_locale": ["$ip local."],
    "rien_a_signaler": ["Rien."],
    "lignes_rejetees": ["$nombre rejets."],
    "conclusion": ["Fin."],
}


@pytest.fixture
def ecrire_modeles(tmp_path):
    """Écrit un fichier de modèles : objet Python (sérialisé), texte ou octets."""

    def _ecrire(contenu: object) -> object:
        chemin = tmp_path / "modeles.json"
        if isinstance(contenu, bytes):
            chemin.write_bytes(contenu)
        elif isinstance(contenu, str):
            chemin.write_text(contenu, encoding="utf-8")
        else:
            chemin.write_text(json.dumps(contenu, ensure_ascii=False), encoding="utf-8")
        return chemin

    return _ecrire


def refus(chemin) -> str:
    """Message de l'ErreurModeles levée ; toute autre issue échoue par assertion."""
    try:
        charger_modeles(chemin)
    except Exception as erreur:  # noqa: BLE001 - le type est vérifié juste après
        assert isinstance(erreur, ErreurModeles), f"{type(erreur).__name__}: {erreur}"
        return str(erreur)
    raise AssertionError("aucune ErreurModeles levée")


def avec(**remplacements: object) -> dict[str, object]:
    return {**VALIDES, **remplacements}


class TestChargement:
    def test_fichier_valide_charge_en_tuples(self, ecrire_modeles):
        modeles = charger_modeles(ecrire_modeles(VALIDES))

        assert modeles == Modeles(**{c: tuple(v) for c, v in VALIDES.items()})

    def test_bom_utf8_accepte(self, ecrire_modeles):
        texte = json.dumps(VALIDES, ensure_ascii=False)

        modeles = charger_modeles(ecrire_modeles(texte.encode("utf-8-sig")))

        assert modeles.entete == tuple(VALIDES["entete"])

    def test_modeles_non_modifiables(self, ecrire_modeles):
        modeles = charger_modeles(ecrire_modeles(VALIDES))

        with pytest.raises(AttributeError):
            modeles.entete = ("Autre.",)  # type: ignore[misc]


class TestFichierInvalide:
    def test_json_invalide_refuse(self, ecrire_modeles):
        assert "JSON invalide" in refus(ecrire_modeles('{"entete": ['))

    def test_encodage_autre_qu_utf8_refuse(self, ecrire_modeles):
        modeles = avec(conclusion=["Fin du rapport. Écartés."])
        texte = json.dumps(modeles, ensure_ascii=False)

        message = refus(ecrire_modeles(texte.encode("cp1252")))

        assert "encodage invalide : UTF-8 attendu" in message

    @pytest.mark.parametrize("racine", [[], "texte", 3, None])
    def test_racine_autre_qu_un_objet_refusee(self, ecrire_modeles, racine):
        assert "objet JSON attendu" in refus(ecrire_modeles(json.dumps(racine)))


class TestCles:
    def test_cle_absente_nommee(self, ecrire_modeles):
        incomplet = {c: v for c, v in VALIDES.items() if c != "conclusion"}

        assert "clé(s) absente(s) : conclusion" in refus(ecrire_modeles(incomplet))

    def test_cle_inconnue_nommee(self, ecrire_modeles):
        # Faute de frappe typique : la clé visée resterait sans effet.
        message = refus(ecrire_modeles(avec(conclusions=["Fin."])))

        assert "clé(s) inconnue(s) : conclusions" in message

    def test_cle_en_double_refusee(self, ecrire_modeles):
        # json garderait la dernière valeur sans rien dire.
        texte = json.dumps(VALIDES, ensure_ascii=False)
        texte = texte.replace('"conclusion"', '"conclusion": ["Autre."], "conclusion"')

        assert "clé en double : conclusion" in refus(ecrire_modeles(texte))


class TestVariantes:
    @pytest.mark.parametrize(
        ("valeur", "attendu"),
        [
            ("Fin.", "conclusion : liste de variantes attendue"),
            ({"a": "Fin."}, "conclusion : liste de variantes attendue"),
            ([], "conclusion : au moins une variante attendue"),
            (["Fin.", 3], "conclusion, variante 2 : texte non vide attendu"),
            (["Fin.", None], "conclusion, variante 2 : texte non vide attendu"),
            (["  "], "conclusion, variante 1 : texte non vide attendu"),
        ],
        ids=["chaine", "objet", "liste-vide", "nombre", "null", "blanc"],
    )
    def test_variantes_mal_formees_refusees(self, ecrire_modeles, valeur, attendu):
        assert attendu in refus(ecrire_modeles(avec(conclusion=valeur)))

    @pytest.mark.parametrize(
        "variante",
        ["Coût : 5 $.", "${ip", "$ 5", "$1"],
        ids=["dollar-seul", "accolade-ouverte", "dollar-espace", "dollar-chiffre"],
    )
    def test_syntaxe_de_modele_invalide_refusee(self, ecrire_modeles, variante):
        message = refus(ecrire_modeles(avec(alerte=["$ip.", variante])))

        assert "alerte, variante 2 : modèle invalide" in message

    def test_demi_codet_isole_refuse(self, ecrire_modeles):
        # JSON accepte "\ud800", mais aucun encodage de sortie ne l'écrirait.
        texte = json.dumps(avec(conclusion=["Fin.", "Fin \ud800."]))

        message = refus(ecrire_modeles(texte))

        assert "conclusion, variante 2 : demi-codet isolé \\ud800" in message

    def test_dollar_double_accepte(self, ecrire_modeles):
        modeles = charger_modeles(ecrire_modeles(avec(conclusion=["Coût : 5 $$."])))

        assert modeles.conclusion == ("Coût : 5 $$.",)


class TestChamps:
    @pytest.mark.parametrize(
        ("cle", "variante", "interdit"),
        [
            ("alerte", "$ip $inconnu.", "$inconnu"),
            ("alerte", "${compte}.", "$compte"),
            ("entete", "$ip.", "$ip"),
            ("rien_a_signaler", "$nombre.", "$nombre"),
            ("conclusion", "$comptes.", "$comptes"),
            ("lignes_rejetees", "$total.", "$total"),
        ],
    )
    def test_champ_non_autorise_pour_la_cle_refuse(
        self, ecrire_modeles, cle, variante, interdit
    ):
        message = refus(ecrire_modeles(avec(**{cle: [variante]})))

        assert f"{cle}, variante 1 : champ(s) non autorisé(s) : {interdit}" in message

    @pytest.mark.parametrize(
        ("cle", "variante"),
        [
            (
                "alerte",
                "$ip $nombre $duree $comptes $seuil $fenetre $total $debut $fin",
            ),
            ("alerte_locale", "${ip} $nombre $duree $comptes $total $debut $fin"),
            ("entete", "$seuil $fenetre"),
            ("rien_a_signaler", "$seuil $fenetre"),
            ("lignes_rejetees", "$nombre $seuil $fenetre"),
            ("conclusion", "$seuil $fenetre"),
        ],
    )
    def test_champs_autorises_acceptes(self, ecrire_modeles, cle, variante):
        modeles = charger_modeles(ecrire_modeles(avec(**{cle: [variante]})))

        assert getattr(modeles, cle) == (variante,)
