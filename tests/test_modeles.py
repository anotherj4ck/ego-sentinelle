import json
from pathlib import Path

import pytest

from ego.modeles import ErreurModeles, Modeles, charger_modeles

# Les six clés obligatoires et les quatre optionnelles du rapport HTML.
MODELES_HTML = Path(__file__).parent / "donnees" / "modeles_html.json"
CLES_OPTIONNELLES = ("titre_alerte", "titre_calme", "registre", "fin_lecture")

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


def charge(chemin) -> Modeles:
    """Modèles chargés ; tout refus échoue par assertion."""
    try:
        return charger_modeles(chemin)
    except Exception as erreur:  # noqa: BLE001 - rendu lisible par l'assertion
        raise AssertionError(f"refusé : {type(erreur).__name__}: {erreur}") from None


def construits(**variantes: tuple[str, ...]) -> Modeles:
    """Modeles construits directement ; toute exception échoue par assertion."""
    try:
        return Modeles(**variantes)
    except Exception as erreur:  # noqa: BLE001 - rendu lisible par l'assertion
        raise AssertionError(f"refusé : {type(erreur).__name__}: {erreur}") from None


def optionnelles(modeles: Modeles) -> dict[str, object]:
    return {cle: getattr(modeles, cle, "attribut absent") for cle in CLES_OPTIONNELLES}


EN_TUPLES = {c: tuple(v) for c, v in VALIDES.items()}


class TestClesOptionnelles:
    def test_absentes_exposees_comme_none(self, ecrire_modeles):
        # Le ego.json actuel n'a que les six clés : il doit rester valide.
        modeles = charge(ecrire_modeles(VALIDES))

        assert optionnelles(modeles) == dict.fromkeys(CLES_OPTIONNELLES)

    def test_fichier_complet_charge_avec_ses_variantes(self):
        attendu = json.loads(MODELES_HTML.read_text(encoding="utf-8"))

        modeles = charge(MODELES_HTML)

        assert optionnelles(modeles) == {
            cle: tuple(attendu[cle]) for cle in CLES_OPTIONNELLES
        }
        assert modeles == construits(**{c: tuple(v) for c, v in attendu.items()})

    def test_une_seule_presente_les_autres_none(self, ecrire_modeles):
        modeles = charge(ecrire_modeles(avec(registre=["$nombre noms."])))

        assert optionnelles(modeles) == {
            **dict.fromkeys(CLES_OPTIONNELLES),
            "registre": ("$nombre noms.",),
        }

    def test_construction_directe_sans_cles_optionnelles(self):
        modeles = construits(**EN_TUPLES)

        assert optionnelles(modeles) == dict.fromkeys(CLES_OPTIONNELLES)

    def test_construction_directe_validee(self):
        try:
            Modeles(**EN_TUPLES, fin_lecture=("$ip.",))  # type: ignore[call-arg]
        except Exception as erreur:  # noqa: BLE001 - le type est vérifié juste après
            message = f"{type(erreur).__name__}: {erreur}"
        else:
            message = "aucune exception"

        assert message.startswith("ErreurModeles: fin_lecture, variante 1 : champ")

    def test_cle_voisine_inconnue_refusee(self, ecrire_modeles):
        message = refus(ecrire_modeles(avec(titre_alertes=["$nombre."])))

        assert "clé(s) inconnue(s) : titre_alertes" in message

    @pytest.mark.parametrize(
        ("valeur", "attendu"),
        [
            # null n'est pas une absence : pour omettre la clé, on la retire.
            (None, "titre_alerte : liste de variantes attendue"),
            ("$nombre.", "titre_alerte : liste de variantes attendue"),
            ([], "titre_alerte : au moins une variante attendue"),
            ([""], "titre_alerte, variante 1 : texte non vide attendu"),
            (["$nombre.", "Coût : 5 $."], "titre_alerte, variante 2 : modèle invalide"),
        ],
        ids=["null", "chaine", "liste-vide", "vide", "dollar-seul"],
    )
    def test_variantes_mal_formees_refusees(self, ecrire_modeles, valeur, attendu):
        assert attendu in refus(ecrire_modeles(avec(titre_alerte=valeur)))

    @pytest.mark.parametrize("cle", CLES_OPTIONNELLES)
    def test_demi_codet_isole_refuse(self, ecrire_modeles, cle):
        texte = json.dumps(avec(**{cle: ["Lu.", "Lu \udfff."]}))

        message = refus(ecrire_modeles(texte))

        assert f"{cle}, variante 2 : demi-codet isolé \\udfff" in message

    @pytest.mark.parametrize(
        ("cle", "variante", "interdit", "autorises"),
        [
            ("titre_alerte", "$nombre $total.", "$total", "(autorisés : $nombre)"),
            ("titre_alerte", "$seuil.", "$seuil", "(autorisés : $nombre)"),
            ("titre_calme", "$nombre.", "$nombre", "(autorisés : $total)"),
            ("titre_calme", "${fenetre}.", "$fenetre", "(autorisés : $total)"),
            ("registre", "$comptes.", "$comptes", "(autorisés : $nombre)"),
            ("fin_lecture", "$nombre.", "$nombre", "(aucun champ autorisé)"),
            ("fin_lecture", "${seuil}.", "$seuil", "(aucun champ autorisé)"),
        ],
    )
    def test_champ_non_autorise_refuse(
        self, ecrire_modeles, cle, variante, interdit, autorises
    ):
        message = refus(ecrire_modeles(avec(**{cle: ["Lu.", variante]})))

        assert (
            f"{cle}, variante 2 : champ(s) non autorisé(s) : {interdit} {autorises}"
            in message
        )

    @pytest.mark.parametrize(
        ("cle", "variante"),
        [
            ("titre_alerte", "$nombre alertes. ${nombre} encore."),
            ("titre_calme", "${total} échecs. $total lus."),
            ("registre", "$nombre noms."),
            ("fin_lecture", "Fin. Coût : 5 $$."),
        ],
    )
    def test_champs_autorises_acceptes(self, ecrire_modeles, cle, variante):
        modeles = charge(ecrire_modeles(avec(**{cle: [variante, "Autre."]})))

        assert optionnelles(modeles)[cle] == (variante, "Autre.")
