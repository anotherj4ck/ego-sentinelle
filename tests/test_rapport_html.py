"""Rapport HTML : structure, sécurité et bornes de taille.

Modèles neutres et repérables : la voix d'Ego est testée dans test_voix_ego.py.
Le texte visible est relu avec html.parser, entités décodées : une valeur
« affichée comme du texte » y figure telle quelle, sans balise dans le document.
"""

import html
import re
import unicodedata
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from ipaddress import ip_address
from pathlib import PurePosixPath, PureWindowsPath

import pytest

from ego._redaction import ALERTES_MAX_AFFICHEES
from ego.detection import Alerte
from ego.lecture import LIBELLE_SANS_IP, SANS_IP, LigneRejetee, Raison, SansIP
from ego.modeles import Modeles
from ego.rapport import rediger
from ego.rapport_html import rediger_html

PLUS_UNE_HEURE = timezone(timedelta(hours=1))
T0 = datetime(2026, 11, 3, 8, 0, tzinfo=PLUS_UNE_HEURE)
GENERE_LE = datetime(2026, 11, 4, 10, 0, tzinfo=PLUS_UNE_HEURE)
FENETRE = timedelta(minutes=10)
RLO = "\N{RIGHT-TO-LEFT OVERRIDE}"
BARRE = "\N{REVERSE SOLIDUS}"
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none';"
    " form-action 'none'"
)
KIO = 1024

MODELES = Modeles(
    entete=("ENTETE seuil=$seuil fenetre=$fenetre",),
    alerte=("ALERTE ip=$ip comptes=[$comptes]", "ALERTE-BIS ip=$ip nombre=$nombre"),
    alerte_locale=("LOCALE ip=$ip comptes=[$comptes]",),
    rien_a_signaler=("RIEN seuil=$seuil",),
    lignes_rejetees=("REJETS nombre=$nombre",),
    conclusion=("CONCLUSION fenetre=$fenetre",),
    titre_alerte=("TITRE_ALERTE nombre=$nombre",),
    titre_calme=("TITRE_CALME total=$total",),
    registre=("REGISTRE nombre=$nombre",),
    fin_lecture=("FIN_LECTURE",),
)
SANS_OPTIONNELLES = replace(
    MODELES, titre_alerte=None, titre_calme=None, registre=None, fin_lecture=None
)

BALISES_PERMISES = frozenset(
    "html head meta title style body header main footer section article"
    " h1 h2 h3 p dl dt dd ul li table thead tbody tr th td".split()
    # Décor de l'étape 3b, au strict nécessaire :
    # div : page, nerf, fente, séparateurs, corps des alertes (blocs sans sens) ;
    # span : adresses de marge, nœud et fil, marques « ∆ SUJET », étiquettes ;
    # code : nom de la source et détail des rejets (valeurs brutes) ;
    # strong : pic d'une alerte ;
    # svg, path : craquelures du nerf, dessin statique.
    + "div span code strong svg path".split()
)
ATTRIBUTS_PERMIS = frozenset(
    {"lang", "charset", "http-equiv", "content", "name", "class"}
    # aria-hidden : masque le décor aux lecteurs d'écran ;
    # viewbox (viewBox, mis en minuscules par html.parser), d : géométrie du SVG.
    | {"aria-hidden", "viewbox", "d"}
)
# Classes du décor : toutes portent aria-hidden="true".
CLASSES_DECOR = frozenset(
    "nerf fente craquelures machine octets separateur adresse noeud marque"
    " etiquette".split()
)
POLICES_SYSTEME = frozenset(
    {"Consolas", "Cascadia Mono", "ui-monospace", "monospace", "Georgia",
     "Times New Roman", "serif"}
)  # fmt: skip
# Paires (texte, fond) de variables CSS portant du vrai texte : WCAG AA, 4,5:1.
# Les variables --decor-* ne colorent que du décor masqué (aria-hidden).
PAIRES_DE_CONTRASTE = [
    ("--texte", "--fond"),
    ("--voix", "--fond"),
    ("--gris", "--fond"),
    ("--orange", "--fond"),
    ("--signal", "--fond"),
    ("--ambre", "--fond"),
    ("--ambre-voix", "--fond"),
    ("--fond", "--orange"),
    ("--texte", "--badge-calme"),
    ("--texte", "--code"),
    ("--gris", "--code"),
]
TITRE_NEUTRE = "<h1>Rapport de surveillance</h1>"
REGISTRE_NEUTRE = '<p class="replique">Registre</p>'
FIN_NEUTRE = '<p class="replique">Fin du rapport</p>'


def alerte(
    ip: str | SansIP = "203.0.113.66",
    comptes: tuple[str, ...] = ("admin", "root"),
    pic: int = 6,
    total: int = 9,
) -> Alerte:
    return Alerte(
        ip=ip_address(ip) if isinstance(ip, str) else ip,
        pic=pic,
        debut_pic=T0,
        fin_pic=T0 + timedelta(minutes=1, seconds=57),
        total=total,
        comptes=comptes,
    )


def rejet(numero: int = 16, detail: str = "-") -> LigneRejetee:
    return LigneRejetee(numero, Raison.IP_ABSENTE, detail)


def rendre(alertes=(), rejets=(), modeles: Modeles = MODELES, **options) -> str:
    parametres = {
        "total_echecs": 120,
        "origines": 7,
        "periode": (T0, T0 + timedelta(hours=1)),
        "source": "echecs.csv",
        "genere_le": GENERE_LE,
        **options,
    }
    return rediger_html(list(alertes), list(rejets), 5, FENETRE, modeles, **parametres)


class Analyse(HTMLParser):
    """Balises, attributs et texte visible (entités décodées) d'un document.

    Suit aussi l'imbrication d'aria-hidden : texte_accessible ne garde que ce
    qu'un lecteur d'écran lit.
    """

    VIDES = frozenset({"meta"})  # éléments sans balise fermante

    def __init__(self, document: str) -> None:
        super().__init__(convert_charrefs=True)
        self.balises: list[str] = []
        self.attributs: list[tuple[str, str | None]] = []
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.metas: list[dict[str, str | None]] = []
        self.morceaux: list[str] = []
        self.accessibles: list[str] = []
        self._masques: list[bool] = []
        self.feed(document)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.balises.append(tag)
        self.attributs.extend(attrs)
        self.elements.append((tag, dict(attrs)))
        if tag == "meta":
            self.metas.append(dict(attrs))
        if tag not in self.VIDES:
            masque = dict(attrs).get("aria-hidden") == "true"
            self._masques.append(masque or any(self._masques))

    def handle_endtag(self, tag):
        if tag not in self.VIDES and self._masques:
            self._masques.pop()

    def handle_data(self, data):
        self.morceaux.append(data)
        if not any(self._masques):
            self.accessibles.append(data)

    @property
    def texte(self) -> str:
        return "".join(self.morceaux)

    @property
    def texte_accessible(self) -> str:
        return "".join(self.accessibles)


def texte(document: str) -> str:
    return Analyse(document).texte


def hostile() -> str:
    """Rapport dont chaque valeur venue de l'export est piégée."""
    return rendre(
        [alerte(comptes=("<script>alert(1)</script>", f'" onmouseover="x{RLO}'))],
        [rejet(detail='"><img src=x onerror=alert(1)>')],
        source='C:/x/"><svg onload=alert(1)>.csv',
    )


class TestDocument:
    def test_debut_du_document(self):
        sortie = rendre()

        assert sortie.startswith(
            '<!DOCTYPE html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n'
        )

    def test_metas_de_securite(self):
        metas = Analyse(rendre()).metas

        assert metas[:1] == [{"charset": "utf-8"}]
        assert {"http-equiv": "Content-Security-Policy", "content": CSP} in metas
        assert {"name": "referrer", "content": "no-referrer"} in metas
        assert {
            "name": "viewport",
            "content": "width=device-width, initial-scale=1",
        } in metas

    def test_sections_dans_l_ordre(self):
        visible = texte(rendre([alerte()], [rejet()]))
        marqueurs = [
            "echecs.csv",
            "2026-11-03 08:00:00 UTC+01:00 → 2026-11-03 09:00:00 UTC+01:00",
            "5 échecs en 10 minutes",
            "120 échecs · 7 origines · 1 ligne rejetée",
            "ALERTE · CODE 1",
            "TITRE_ALERTE nombre=1",
            "ENTETE seuil=5 fenetre=10 minutes",
            "Alertes",
            "ALERTE ip=203.0.113.66 comptes=[admin, root]",
            "Lignes rejetées",
            "REJETS nombre=1",
            "REGISTRE nombre=3",
            "CONCLUSION fenetre=10 minutes",
            "FIN_LECTURE",
            "Généré le 2026-11-04 10:00:00 UTC+01:00 · fichier statique, aucun script",
        ]

        assert [m for m in marqueurs if m not in visible] == []
        positions = [visible.index(m) for m in marqueurs]
        assert positions == sorted(positions)

    def test_bloc_d_alerte(self):
        visible = texte(rendre([alerte()]))

        for attendu in (
            "203.0.113.66",
            "Origineexterne",
            "Pic6 échecs",
            "Fenêtre du pic2026-11-03 08:00:00 UTC+01:00 → 2026-11-03 08:01:57"
            " UTC+01:00 (1 minute 57 secondes)",
            "Total9 échecs",
            "Comptes visésadmin, root",
        ):
            assert attendu in visible

    def test_comptes_plafonnes_comme_le_texte(self):
        comptes = tuple(f"compte{n:02d}" for n in range(12))

        visible = texte(rendre([alerte(comptes=comptes)]))

        assert "compte08, compte09 et 2 autres" in visible

    def test_repliques_identiques_au_rapport_texte(self):
        # Même graine, même rotation des variantes que rediger().
        alertes = [
            alerte("203.0.113.1", total=11),
            alerte("203.0.113.2", total=12),
            alerte("203.0.113.3", total=13),
            alerte("::1", total=14),
        ]
        rapport_texte = rediger(alertes, [rejet()], 5, FENETRE, MODELES)
        repliques = [
            ligne
            for ligne in rapport_texte.splitlines()
            if ligne.startswith(("ALERTE", "LOCALE"))
        ]

        visible = texte(rendre(alertes, [rejet()]))

        assert len(repliques) == 4
        assert [r for r in repliques if r not in visible] == []

    def test_fonction_pure(self):
        premier = rendre([alerte()], [rejet()])

        assert "203.0.113.66" in premier
        assert rendre([alerte()], [rejet()]) == premier

    def test_genere_le_sans_fuseau_refuse(self):
        try:
            rendre(genere_le=datetime(2026, 11, 4, 10, 0))
        except Exception as erreur:  # noqa: BLE001 - le type est vérifié juste après
            message = f"{type(erreur).__name__}: {erreur}"
        else:
            message = "aucune exception"

        assert message == (
            "ValueError: genere_le sans fuseau horaire : 2026-11-04 10:00:00"
        )


class TestSecurite:
    def test_compte_script_affiche_comme_texte(self):
        sortie = rendre([alerte(comptes=("<script>alert(1)</script>",))])

        assert "<script>alert(1)</script>" in texte(sortie)
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in sortie
        assert "<script" not in sortie

    def test_detail_de_rejet_affiche_comme_texte(self):
        detail = '"><img src=x onerror=alert(1)>'

        sortie = rendre(rejets=[rejet(detail=detail)])

        assert detail in texte(sortie)
        assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in sortie
        assert "<img" not in sortie

    def test_compte_bidi_affiche_echappe(self):
        sortie = rendre([alerte(comptes=(f"admin{RLO}nimda",))])

        assert f"admin{BARRE}u202enimda" in texte(sortie)
        assert RLO not in sortie

    def test_ip_avec_zone_piegee_neutralisee(self):
        # ipaddress accepte « fe80::1%<zone> » ; la lecture le refuse, mais
        # rediger_html ne doit pas compter sur elle.
        sortie = rendre([alerte(f"fe80::1%<b>{RLO}")])

        assert f"fe80::1%<b>{BARRE}u202e" in texte(sortie)
        assert "b" not in Analyse(sortie).balises
        assert RLO not in sortie

    def test_ip_neutralisee_une_seule_fois(self):
        # Titre du bloc, réplique et registre : une barre de la zone devient
        # deux, jamais quatre.
        visible = texte(rendre([alerte(f"fe80::1%a{BARRE}c", comptes=("root",))]))

        assert visible.count(f"fe80::1%a{BARRE * 2}c") == 3
        assert BARRE * 3 not in visible

    def test_replique_avec_balise_affichee_litteralement(self):
        modeles = replace(MODELES, entete=("<b>gras</b> & co",))

        sortie = rendre(modeles=modeles)

        assert "<b>gras</b> & co" in texte(sortie)
        assert "&lt;b&gt;gras&lt;/b&gt; &amp; co" in sortie
        assert "b" not in Analyse(sortie).balises

    def test_valeur_substituee_puis_echappee_une_seule_fois(self):
        # Échapper avant la substitution, puis la chaîne entière, afficherait
        # « &lt;a&amp;b&gt; » au lecteur.
        modeles = replace(MODELES, alerte=("ALERTE comptes=[$comptes]",))

        visible = texte(rendre([alerte(comptes=("<a&b>",))], modeles=modeles))

        assert "comptes=[<a&b>]" in visible
        assert "&lt;" not in visible and "&amp;" not in visible

    def test_barre_oblique_doublee_une_seule_fois(self):
        # neutraliser() n'est pas idempotent : appliqué deux fois, une barre
        # deviendrait quatre.
        compte = f"dom{BARRE}admin"
        detail = f"C:{BARRE}tmp"

        visible = texte(rendre([alerte(comptes=(compte,))], [rejet(detail=detail)]))

        # Bloc d'alerte, réplique et registre.
        assert visible.count(f"dom{BARRE * 2}admin") == 3
        assert f"C:{BARRE * 2}tmp" in visible
        assert BARRE * 3 not in visible

    def test_aucun_caractere_invisible_en_sortie(self):
        compte = f"a\x1b[31m{RLO}\N{LINE SEPARATOR}\N{ZERO WIDTH SPACE}b"

        sortie = rendre([alerte(comptes=(compte,))], [rejet(detail=compte)])

        assert f"a{BARRE}x1b[31m{BARRE}u202e{BARRE}u2028{BARRE}u200bb" in texte(sortie)
        invisibles = sorted(
            {
                f"U+{ord(c):04X}"
                for c in sortie
                if c != "\n" and unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"}
            }
        )
        assert invisibles == []

    @pytest.mark.parametrize(
        "source",
        [
            BARRE.join(["C:", "Users", "Admin", "exports", "echecs.csv"]),
            PureWindowsPath("C:/Users/Admin/exports/echecs.csv"),
            "/home/Admin/exports/echecs.csv",
            PurePosixPath("/home/Admin/exports/echecs.csv"),
        ],
        ids=["windows-texte", "windows-chemin", "posix-texte", "posix-chemin"],
    )
    def test_seul_le_nom_du_fichier_source(self, source):
        sortie = rendre(source=source)

        assert "echecs.csv" in texte(sortie)
        assert "Admin" not in sortie
        assert "exports" not in sortie

    def test_structure_sur_donnees_hostiles(self):
        analyse = Analyse(hostile())

        noms = {nom for nom, _ in analyse.attributs}
        valeurs = [valeur or "" for _, valeur in analyse.attributs]
        assert set(analyse.balises) <= BALISES_PERMISES
        assert noms <= ATTRIBUTS_PERMIS
        assert [nom for nom in noms if nom.startswith("on")] == []
        assert [v for v in valeurs if "javascript:" in v.lower()] == []
        csp = {"http-equiv": "Content-Security-Policy", "content": CSP}
        assert csp in analyse.metas

    def test_aucune_valeur_dynamique_dans_un_attribut(self):
        # Les attributs d'un rapport piégé sont exactement ceux d'un rapport sain.
        sain = Analyse(rendre([alerte()], [rejet()])).attributs

        assert ("class", "alerte externe") in sain
        assert set(Analyse(hostile()).attributs) == set(sain)

    def test_attributs_identiques_avec_l_origine_sans_ip(self):
        piege = ("<script>alert(1)</script>", f'" onmouseover="x{RLO}', "-")
        sain = Analyse(rendre([alerte(), alerte(SANS_IP)], [rejet()])).attributs
        hostile_sans_ip = rendre(
            [alerte(comptes=piege), alerte(SANS_IP, comptes=piege)],
            [rejet(detail='"><img src=x onerror=alert(1)>')],
            source='C:/x/"><svg onload=alert(1)>.csv',
        )

        assert ("class", "alerte locale") in sain
        assert set(Analyse(hostile_sans_ip).attributs) == set(sain)

    def test_valeurs_piegees_visibles_comme_texte(self):
        visible = texte(hostile())

        for attendu in (
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>.csv',
        ):
            assert attendu in visible


class TestClesOptionnelles:
    @pytest.mark.parametrize(
        ("cle", "alertes", "marqueur", "neutre"),
        [
            ("titre_alerte", [alerte()], "TITRE_ALERTE", TITRE_NEUTRE),
            ("titre_calme", [], "TITRE_CALME", TITRE_NEUTRE),
            # « REGISTRE nombre= » : la réplique de test, pas le séparateur décoratif
            # « ∆ REGISTRE ░▒ … » de l'étape 3b.
            ("registre", [alerte()], "REGISTRE nombre=", REGISTRE_NEUTRE),
            ("fin_lecture", [alerte()], "FIN_LECTURE", FIN_NEUTRE),
        ],
    )
    def test_cle_absente_remplacee_par_un_texte_neutre(
        self, cle, alertes, marqueur, neutre
    ):
        sortie = rendre(alertes, modeles=replace(MODELES, **{cle: None}))

        assert neutre in sortie
        assert marqueur not in sortie

    @pytest.mark.parametrize("alertes", [[], [alerte()]], ids=["calme", "alerte"])
    def test_toutes_absentes(self, alertes):
        sortie = rendre(alertes, modeles=SANS_OPTIONNELLES)

        assert TITRE_NEUTRE in sortie
        assert FIN_NEUTRE in sortie


class TestCas:
    def test_aucune_alerte(self):
        sortie = rendre()
        visible = texte(sortie)

        assert "SILENCE · CODE 0" in visible
        assert "TITRE_CALME total=120" in visible
        assert "RIEN seuil=5" in visible
        assert "FIN_LECTURE" in visible
        for absent in ("CONCLUSION", "REGISTRE", "Alertes", 'class="registre"'):
            assert absent not in sortie

    def test_alertes_locales_seules(self):
        visible = texte(rendre([alerte("::1")]))

        assert "ALERTE · CODE 1" in visible
        assert "Originelocale" in visible
        assert "LOCALE ip=::1 comptes=[admin, root]" in visible

    def test_export_vide(self):
        visible = texte(rendre(periode=None, total_echecs=0, origines=0))

        assert "Périodeaucun événement lu" in visible
        assert "0 échec · 0 origine · 0 ligne rejetée" in visible
        assert "TITRE_CALME total=0" in visible

    def test_rejets_plafonnes_a_vingt(self):
        rejets = [rejet(numero=n) for n in range(2, 27)]

        sortie = rendre(rejets=rejets)

        assert sortie.count("<tr>") == 1 + 20  # en-tête du tableau + 20 lignes
        assert "… et 5 autres" in texte(sortie)
        assert "REJETS nombre=25" in texte(sortie)

    def test_registre_avec_noms_masques(self):
        comptes = tuple(f"compte{n:02d}" for n in range(60))

        visible = texte(rendre([alerte(comptes=comptes)]))

        assert "REGISTRE nombre=61" in visible
        assert "+ 11 autres" in visible

    def test_registre_sans_nom_masque(self):
        visible = texte(rendre([alerte()]))

        assert "REGISTRE nombre=3" in visible
        assert re.search(r"\+ \d+ autre", visible) is None


class TestBornes:
    """Bornes de taille du document, en octets UTF-8.

    Un nom affiché fait au plus 64 caractères. La neutralisation le multiplie
    au pire par 10 (un caractère de format hors plan de base devient
    « \\U000e0001 ») ; html.escape ne fait pas pire (« < » devient « &lt; »).
    Une alerte montre au plus 10 comptes deux fois (bloc et réplique), soit
    13 Kio au pire ; le registre au plus 50 noms, 32 Kio au pire ; le squelette,
    le décor et le CSS de l'étape 3b environ 9 Kio. Pire cas d'une alerte de
    5 000 comptes : 54 Kio, d'où 64 Kio avec une marge. Avec des noms
    ordinaires : 16 Kio (11 Kio mesurés).
    """

    def test_5000_comptes_ordinaires(self):
        comptes = tuple(f"compte{n:04d}" for n in range(5000))

        sortie = rendre([alerte(comptes=comptes)])

        assert len(sortie.encode("utf-8")) <= 16 * KIO
        visible = texte(sortie)
        assert "compte0009 et 4990 autres" in visible
        assert "+ 4951 autres" in visible
        assert "compte0049" not in visible

    def test_5000_comptes_pieges_pire_cas(self):
        comptes = tuple(f"{n:04d}" + "\N{LANGUAGE TAG}" * 60 for n in range(5000))

        sortie = rendre([alerte(comptes=comptes)])

        assert len(sortie.encode("utf-8")) <= 64 * KIO
        assert "+ 4951 autres" in texte(sortie)

    def test_plafond_des_alertes(self):
        assert ALERTES_MAX_AFFICHEES == 200

    def test_250_alertes_plafonnees_a_200(self):
        alertes = [alerte(f"192.0.2.{n}", comptes=("admin",)) for n in range(250)]

        sortie = rendre(alertes)
        visible = texte(sortie)

        assert sortie.count("<article ") == 200
        assert "+ 50 alertes non affichées" in visible
        assert "192.0.2.199" in visible
        assert "192.0.2.249" not in visible
        # En-tête et registre portent sur toutes les alertes.
        assert "TITRE_ALERTE nombre=250" in visible
        assert "REGISTRE nombre=251" in visible
        assert "+ 201 autres" in visible

    def test_une_seule_alerte_masquee_au_singulier(self):
        alertes = [alerte(f"192.0.2.{n}", comptes=("admin",)) for n in range(201)]

        assert "+ 1 alerte non affichée" in texte(rendre(alertes))


def css(document: str) -> str:
    """Contenu de l'unique élément <style>."""
    debut = document.index("<style>") + len("<style>")
    return document[debut : document.index("</style>")]


def bloc_media(feuille: str, condition: str) -> str:
    """Corps du bloc « @media <condition> { … } », accolades équilibrées."""
    debut = feuille.find(f"@media {condition}")
    assert debut >= 0, f"aucun bloc @media {condition}"
    ouverture = feuille.index("{", debut)
    profondeur = 0
    for position in range(ouverture, len(feuille)):
        profondeur += {"{": 1, "}": -1}.get(feuille[position], 0)
        if profondeur == 0:
            return feuille[ouverture + 1 : position]
    raise AssertionError(f"bloc @media {condition} non fermé")


def variables(feuille: str) -> dict[str, str]:
    """Variables de couleur du bloc :root : {"--fond": "#0A0706", …}."""
    racine = re.search(r":root\s*\{([^}]*)\}", feuille)
    assert racine, "aucun bloc :root"
    return dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9A-Fa-f]{6})", racine.group(1)))


def contraste(premier: str, second: str) -> float:
    """Rapport de contraste WCAG 2 entre deux couleurs #RRGGBB."""

    def luminance(couleur: str) -> float:
        composantes = [int(couleur[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        lineaires = [
            c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
            for c in composantes
        ]
        return 0.2126 * lineaires[0] + 0.7152 * lineaires[1] + 0.0722 * lineaires[2]

    clair, sombre = sorted((luminance(premier), luminance(second)), reverse=True)
    return (clair + 0.05) / (sombre + 0.05)


def trois_alertes() -> list[Alerte]:
    return [alerte("203.0.113.1"), alerte("203.0.113.2"), alerte("::1")]


class TestEsthetique:
    def test_classe_d_etat_sur_body(self):
        assert '<body class="etat-alerte">' in rendre([alerte()])
        assert '<body class="etat-silence">' in rendre()

    def test_entete_machine(self):
        visible = texte(rendre([alerte()]))

        assert "∆ SYSTÈME EGO // ARCHIVE — SENTINELLE" in visible
        assert "∆ NOYAU BYPASS // CORROMPU À 42 %" in visible

    def test_separateurs_avec_compteurs_reels(self):
        visible = texte(rendre(trois_alertes(), [rejet(16), rejet(17)]))
        separateurs = [
            "∆ SUJETS ░▒ 03",
            "Alertes",
            "∆ SECTEURS ILLISIBLES ░▒ 02",
            "Lignes rejetées",
            "∆ REGISTRE ░▒ 05 ENTRÉES",
            "Registre",
        ]

        assert [s for s in separateurs if s not in visible] == []
        positions = [visible.index(s) for s in separateurs]
        assert positions == sorted(positions)

    def test_separateurs_en_silence(self):
        visible = texte(rendre())

        assert "∆ SUJETS ░▒ 00" in visible
        assert "SECTEURS ILLISIBLES" not in visible
        assert "∆ REGISTRE" not in visible

    def test_compteur_de_sujets_sur_toutes_les_alertes(self):
        alertes = [alerte(f"192.0.2.{n}", comptes=("admin",)) for n in range(250)]

        assert "∆ SUJETS ░▒ 250" in texte(rendre(alertes))

    def test_registre_d_une_seule_entree_au_singulier(self):
        visible = texte(rendre([alerte(comptes=())]))

        assert "∆ REGISTRE ░▒ 01 ENTRÉE " in visible

    def test_sujets_externe_et_local(self):
        visible = texte(rendre(trois_alertes()))

        assert "∆ SUJET 203.0.113.1 · ALERTE · EXTERNE" in visible
        assert "∆ SUJET ::1 · LOCAL · SANS DOUTE UN TEST" in visible

    def test_origine_sans_ip_etiquette_propre_et_affichage_local(self):
        sortie = rendre([alerte(SANS_IP), alerte("::1")])
        analyse = Analyse(sortie)
        visible = analyse.texte

        assert "∆ SUJET (local, sans IP) · LOCAL · CLAVIER OU SERVICE" in visible
        assert "∆ SUJET ::1 · LOCAL · SANS DOUTE UN TEST" in visible
        # Ambre : la classe « locale », comme ::1.
        articles = [a.get("class") for b, a in analyse.elements if b == "article"]
        assert articles == ["alerte locale", "alerte locale"]
        # Le libellé, échappé, dans le titre de l'alerte et dans le registre.
        echappe = html.escape(LIBELLE_SANS_IP, quote=True)
        assert f"</span>{echappe}<span" in sortie
        assert f"<li>{echappe}</li>" in sortie
        assert LIBELLE_SANS_IP in analyse.texte_accessible

    def test_origine_sans_ip_masquee_en_premier_au_dela_du_plafond(self):
        externes = [alerte(f"192.0.2.{n}", comptes=()) for n in range(200)]
        alertes = [alerte(SANS_IP, pic=99), *externes]  # pic le plus haut

        visible = texte(rendre(alertes))

        assert "∆ SUJET (local, sans IP)" not in visible
        assert "∆ SUJET 192.0.2.199" in visible
        assert "+ 1 alerte non affichée" in visible

    def test_adresses_de_marge_deterministes(self):
        visible = texte(rendre(trois_alertes()))
        adresses = ["0x00A0", "0x0140", "0x01E0"]

        positions = [visible.find(a) for a in adresses]
        assert -1 not in positions and positions == sorted(positions)
        assert rendre(trois_alertes()) == rendre(trois_alertes())

    def test_adresse_de_la_derniere_alerte_affichee(self):
        alertes = [alerte(f"192.0.2.{n}", comptes=("admin",)) for n in range(250)]

        visible = texte(rendre(alertes))

        assert "0x7D00" in visible  # 200 × 0xA0
        assert "0x7DA0" not in visible

    def test_decor_masque_aux_lecteurs_d_ecran(self):
        analyse = Analyse(rendre(trois_alertes(), [rejet()]))

        decor = [
            (balise, attributs)
            for balise, attributs in analyse.elements
            if balise == "svg"
            or set((attributs.get("class") or "").split()) & CLASSES_DECOR
        ]
        assert {balise for balise, _ in decor} >= {"div", "span", "svg", "p"}
        assert [a for _, a in decor if a.get("aria-hidden") != "true"] == []
        accessible = analyse.texte_accessible
        for decoratif in ("∆", "░", "0x00A0"):
            assert decoratif not in accessible

    def test_informations_lues_par_les_lecteurs_d_ecran(self):
        accessible = Analyse(rendre(trois_alertes(), [rejet()])).texte_accessible

        for attendu in (
            "Sourceechecs.csv",
            "Période2026-11-03 08:00:00 UTC+01:00 → 2026-11-03 09:00:00 UTC+01:00",
            "Seuil5 échecs en 10 minutes",
            "Volume lu120 échecs · 7 origines · 1 ligne rejetée",
            "étatALERTE · CODE 1",
            "TITRE_ALERTE nombre=3",
            "Alertes",
            "203.0.113.1",
            "Originelocale",
            "ip=203.0.113.2",  # réplique de l'alerte, quelle que soit la variante
            "Lignes rejetées",
            "IP absente",
            "Registre",
            "REGISTRE nombre=5",
        ):
            assert attendu in accessible

    def test_etat_lu_avec_son_libelle_en_silence(self):
        accessible = Analyse(rendre()).texte_accessible

        assert "étatSILENCE · CODE 0" in accessible

    def test_titres_de_section_visuellement_masques(self):
        analyse = Analyse(rendre(trois_alertes(), [rejet()]))

        classes = [a.get("class") for balise, a in analyse.elements if balise == "h2"]
        assert classes == ["visuellement-masque"] * 3

    def test_source_et_detail_en_code(self):
        sortie = rendre(rejets=[rejet(detail="999.1.1.1")])

        assert "<dd><code>echecs.csv</code></dd>" in sortie
        assert "<td><code>999.1.1.1</code></td>" in sortie

    def test_un_seul_style_dans_le_head(self):
        sortie = rendre([alerte()])

        assert sortie.count("<style>") == 1
        assert sortie.index("</style>") < sortie.index("</head>")

    def test_css_sans_ressource_externe(self):
        feuille = css(rendre([alerte()])).lower()

        for interdit in ("url(", "@import", "expression(", "@font-face", "http"):
            assert interdit not in feuille

    def test_polices_systeme_uniquement(self):
        feuille = css(rendre([alerte()]))

        familles = {
            police.strip().strip('"')
            for declaration in re.findall(r"font-family\s*:\s*([^;}]+)", feuille)
            for police in declaration.split(",")
        }
        assert familles and familles <= POLICES_SYSTEME
        assert re.search(r"(?<![-\w])font\s*:", feuille) is None  # pas de raccourci

    def test_media_queries_presentes(self):
        feuille = css(rendre([alerte()]))

        for condition in (
            "(prefers-reduced-motion: reduce)",
            "(max-width: 600px)",
            "print",
        ):
            assert f"@media {condition}" in feuille

    def test_animations_coupees_si_mouvement_reduit(self):
        feuille = css(rendre([alerte()]))

        assert "@keyframes" in feuille
        assert "animation: none !important" in bloc_media(
            feuille, "(prefers-reduced-motion: reduce)"
        )

    def test_impression_claire_sans_decor_ni_animation(self):
        bloc = bloc_media(css(rendre([alerte()])), "print")

        assert "background: #fff !important" in bloc
        assert "color: #000 !important" in bloc
        assert '[aria-hidden="true"] { display: none !important; }' in bloc
        assert "animation: none !important" in bloc

    def test_petit_ecran_sans_adresses(self):
        bloc = bloc_media(css(rendre([alerte()])), "(max-width: 600px)")

        assert ".adresse { display: none; }" in bloc

    @pytest.mark.parametrize(("texte_css", "fond_css"), PAIRES_DE_CONTRASTE)
    def test_contraste_du_texte(self, texte_css, fond_css):
        couleurs = variables(css(rendre([alerte()])))

        assert contraste(couleurs[texte_css], couleurs[fond_css]) >= 4.5
