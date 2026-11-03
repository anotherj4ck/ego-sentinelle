from dataclasses import replace
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

import pytest

from ego.detection import Alerte, detecter
from ego.lecture import LigneRejetee, Raison, lire_export
from ego.modeles import Modeles, charger_modeles
from ego.rapport import formater_duree, formater_instant, rediger

EGO = Path(__file__).parent.parent / "modeles" / "ego.json"

PLUS_UNE_HEURE = timezone(timedelta(hours=1))
MOINS_NEUF_HEURES_TRENTE = timezone(-timedelta(hours=9, minutes=30))
T0 = datetime(2026, 11, 3, 8, 0, tzinfo=PLUS_UNE_HEURE)
FENETRE = timedelta(minutes=10)

# Modèles neutres et repérables : la voix d'Ego est testée dans test_voix_ego.py.
MODELES = Modeles(
    entete=("ENTETE seuil=$seuil fenetre=$fenetre",),
    alerte=(
        "ALERTE ip=$ip nombre=$nombre duree=$duree comptes=[$comptes]"
        " seuil=$seuil fenetre=$fenetre total=$total debut=$debut fin=$fin",
    ),
    alerte_locale=("LOCALE ip=$ip nombre=$nombre comptes=[$comptes]",),
    rien_a_signaler=("RIEN seuil=$seuil",),
    lignes_rejetees=("REJETS nombre=$nombre",),
    conclusion=("FIN fenetre=$fenetre",),
)


def alerte(
    ip: str = "192.0.2.10",
    pic: int = 5,
    duree: timedelta = timedelta(minutes=4, seconds=12),
    total: int = 5,
    comptes: tuple[str, ...] = ("admin",),
) -> Alerte:
    return Alerte(
        ip=ip_address(ip),
        pic=pic,
        debut_pic=T0,
        fin_pic=T0 + duree,
        total=total,
        comptes=comptes,
    )


def rapport(alertes=(), rejets=(), modeles: Modeles = MODELES) -> str:
    return rediger(alertes, rejets, seuil=5, fenetre=FENETRE, modeles=modeles)


class TestDuree:
    def test_minutes_et_secondes_en_toutes_lettres(self):
        duree = timedelta(minutes=4, seconds=12)

        assert formater_duree(duree) == "4 minutes 12 secondes"

    @pytest.mark.parametrize(
        ("duree", "attendu"),
        [
            (timedelta(seconds=1), "1 seconde"),
            (timedelta(minutes=1, seconds=1), "1 minute 1 seconde"),
            (timedelta(hours=1), "1 heure"),
            (timedelta(days=1), "1 jour"),
            (timedelta(hours=2, minutes=1), "2 heures 1 minute"),
        ],
    )
    def test_singulier_pour_une_unite(self, duree, attendu):
        assert formater_duree(duree) == attendu

    @pytest.mark.parametrize(
        "duree",
        [timedelta(0), timedelta(microseconds=999_999)],
        ids=["nulle", "presque-une-seconde"],
    )
    def test_moins_d_une_seconde(self, duree):
        # Rafale simultanée : "5 tentatives en moins d'une seconde".
        assert formater_duree(duree) == "moins d'une seconde"

    def test_fractions_de_seconde_tronquees(self):
        duree = timedelta(minutes=4, seconds=12, microseconds=999_999)

        assert formater_duree(duree) == "4 minutes 12 secondes"

    def test_duree_negative_refusee(self):
        with pytest.raises(ValueError, match="durée négative"):
            formater_duree(timedelta(seconds=-1))


class TestInstant:
    @pytest.mark.parametrize(
        ("instant", "attendu"),
        [
            (
                datetime(2026, 11, 3, 2, 14, 5, 100000, tzinfo=PLUS_UNE_HEURE),
                "2026-11-03 02:14:05 UTC+01:00",
            ),
            (
                datetime(2026, 11, 3, 1, 14, 51, tzinfo=timezone.utc),
                "2026-11-03 01:14:51 UTC",
            ),
            (
                datetime(2026, 3, 9, 7, 5, 0, tzinfo=MOINS_NEUF_HEURES_TRENTE),
                "2026-03-09 07:05:00 UTC-09:30",
            ),
            (
                datetime(1, 1, 2, 0, 0, 0, tzinfo=timezone.utc),
                "0001-01-02 00:00:00 UTC",
            ),
        ],
        ids=["decalage-positif", "utc", "decalage-negatif", "an-1"],
    )
    def test_heure_d_origine_avec_son_decalage(self, instant, attendu):
        # Ordre AAAA-MM-JJ : aucune ambiguïté jour/mois.
        assert formater_instant(instant) == attendu


class TestStructure:
    def test_sans_alerte_ni_rejet(self):
        assert rapport() == (
            "ENTETE seuil=5 fenetre=10 minutes\n"
            "\n"
            "RIEN seuil=5\n"
            "\n"
            "FIN fenetre=10 minutes\n"
        )


class TestAlerte:
    def test_alerte_externe_avec_toutes_ses_valeurs(self):
        texte = rapport([alerte(pic=6, total=7, comptes=("admin", "root"))])

        assert texte.split("\n\n")[1] == (
            "ALERTE ip=192.0.2.10 nombre=6 duree=4 minutes 12 secondes"
            " comptes=[admin, root] seuil=5 fenetre=10 minutes total=7"
            " debut=2026-11-03 08:00:00 UTC+01:00 fin=2026-11-03 08:04:12 UTC+01:00"
        )


class TestComptes:
    def test_compte_vide_affiche_sans_nom(self):
        texte = rapport([alerte(comptes=("", "admin"))])

        assert "comptes=[(sans nom), admin]" in texte

    def test_sequence_ansi_dans_un_compte_neutralisee(self):
        # Le nom tenté par l'attaquant tenterait d'effacer l'écran et de
        # réécrire la ligne en rouge.
        hostile = "\x1b[2J\x1b[31mroot\x1b[0m\r\nALERTE ip=8.8.8.8"

        texte = rapport([alerte(comptes=(hostile,))])

        blocs = texte.rstrip("\n").split("\n\n")
        assert "\x1b" not in texte
        assert "\r" not in texte
        assert len(blocs) == 3  # entête, alerte, conclusion : rien d'injecté
        assert "\n" not in blocs[1]
        assert "comptes=[\\x1b[2J\\x1b[31mroot\\x1b[0m\\x0d\\x0aALERTE" in texte

    def test_bidi_dans_un_compte_neutralise(self):
        texte = rapport([alerte(comptes=("admin‮nimda",))])

        assert "‮" not in texte
        assert "comptes=[admin\\u202enimda]" in texte

    def test_dollar_dans_un_compte_reste_litteral(self):
        texte = rapport([alerte(comptes=("$ip", "${seuil}"))])

        assert "comptes=[$ip, ${seuil}]" in texte


class TestSections:
    def test_alertes_locales_a_part_apres_les_externes(self):
        # Ordre de detecter() : pic décroissant. Les locales passent quand même
        # après les externes, chacune dans son bloc, avec son propre modèle.
        alertes = [
            alerte(ip="::1", pic=9),
            alerte(ip="203.0.113.7", pic=7),
            alerte(ip="127.0.0.1", pic=6),
            alerte(ip="192.0.2.10", pic=5),
        ]

        blocs = rapport(alertes).split("\n\n")

        assert [ligne.split()[:2] for ligne in blocs[1].splitlines()] == [
            ["ALERTE", "ip=203.0.113.7"],
            ["ALERTE", "ip=192.0.2.10"],
        ]
        assert blocs[2].splitlines() == [
            "LOCALE ip=::1 nombre=9 comptes=[admin]",
            "LOCALE ip=127.0.0.1 nombre=6 comptes=[admin]",
        ]

    def test_seulement_des_locales_pas_de_rien_a_signaler(self):
        assert rapport([alerte(ip="::1")]) == (
            "ENTETE seuil=5 fenetre=10 minutes\n"
            "\n"
            "LOCALE ip=::1 nombre=5 comptes=[admin]\n"
            "\n"
            "FIN fenetre=10 minutes\n"
        )

    def test_lignes_rejetees_comptees_avant_la_conclusion(self):
        rejets = [
            LigneRejetee(3, Raison.IP_ABSENTE, "-"),
            LigneRejetee(7, Raison.DATE_ILLISIBLE, "hier"),
        ]

        assert rapport(rejets=rejets).split("\n\n")[-2:] == [
            "REJETS nombre=2",
            "FIN fenetre=10 minutes\n",
        ]


def a_variantes(**cles: tuple[str, ...]) -> Modeles:
    return replace(MODELES, **cles)


class TestVariantes:
    def test_alertes_successives_alternent_les_variantes(self):
        modeles = a_variantes(alerte=("V1 $ip", "V2 $ip"))
        alertes = [alerte(ip=f"192.0.2.{n}") for n in (1, 2, 3, 4)]

        lignes = rapport(alertes, modeles=modeles).split("\n\n")[1].splitlines()
        prefixes = [ligne.split()[0] for ligne in lignes]

        assert set(prefixes) == {"V1", "V2"}
        assert all(a != b for a, b in zip(prefixes, prefixes[1:]))

    def test_replique_choisie_selon_les_donnees(self):
        modeles = a_variantes(entete=("E1", "E2"))
        rejet = LigneRejetee(2, Raison.IP_ABSENTE, "-")

        entetes = {rapport(rejets=r, modeles=modeles)[:2] for r in ([], [rejet])}

        assert entetes == {"E1", "E2"}

    def test_memes_donnees_meme_rapport(self):
        modeles = a_variantes(
            entete=("E1", "E2", "E3"), alerte=("V1 $ip", "V2 $ip", "V3 $ip")
        )
        alertes = [alerte(ip="192.0.2.1", total=8), alerte(ip="192.0.2.2", total=6)]

        assert rapport(alertes, modeles=modeles) == rapport(alertes, modeles=modeles)


class TestIntegration:
    def test_export_d_attaque_avec_les_modeles_d_ego(self, donnees):
        lecture = lire_export(donnees / "export_attaque.csv")
        alertes = detecter(lecture.evenements)

        texte = rediger(alertes, lecture.rejets, 5, FENETRE, charger_modeles(EGO))
        blocs = texte.rstrip("\n").split("\n\n")

        assert len(blocs) == 5  # entête, externes, locales, rejets, conclusion
        assert blocs[1].startswith("203.0.113.66. 6 ")
        assert "admin, administrateur, invite, root, sauvegarde" in blocs[1]
        assert blocs[2].startswith("::1. ")
        assert blocs[3].startswith("1 lignes ")

    def test_compte_hostile_neutralise_de_bout_en_bout(self, ecrire_export):
        lignes = [
            f'"2026-11-03T08:0{n}:00+01:00","\x1b[2J\x1b[31mroot\r\n","203.0.113.9"'
            for n in range(5)
        ]
        chemin = ecrire_export(
            ("Date,Compte,IP\n" + "\n".join(lignes) + "\n").encode("utf-8")
        )
        lecture = lire_export(chemin)

        texte = rediger(
            detecter(lecture.evenements), lecture.rejets, 5, FENETRE,
            charger_modeles(EGO),
        )

        assert "\x1b" not in texte and "\r" not in texte
        assert "\\x1b[2J\\x1b[31mroot" in texte
