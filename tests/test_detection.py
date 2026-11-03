from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest

from ego.detection import FENETRE, SEUIL_ECHECS, Alerte, detecter
from ego.lecture import MARGE_CALCUL, Evenement, lire_export

PLUS_UNE_HEURE = timezone(timedelta(hours=1))
T0 = datetime(2026, 11, 3, 8, 0, tzinfo=PLUS_UNE_HEURE)
IP_A = "192.0.2.10"
IP_B = "203.0.113.7"


def ev(
    decalage: timedelta, ip: str = IP_A, compte: str = "admin"
) -> Evenement:
    """Un échec à T0 + decalage."""
    return Evenement(horodatage=T0 + decalage, compte=compte, ip=ip_address(ip))


def minutes(*valeurs: float) -> list[timedelta]:
    return [timedelta(minutes=v) for v in valeurs]


def rafale(*decalages: timedelta, ip: str = IP_A) -> list[Evenement]:
    return [ev(d, ip=ip) for d in decalages]


class TestSeuil:
    def test_seuil_atteint_par_une_ip_seulement(self):
        evenements = rafale(*minutes(0, 1, 2, 3, 4)) + rafale(
            *minutes(0, 1, 2, 3), ip=IP_B
        )

        alertes = detecter(evenements)

        assert [(str(a.ip), a.pic) for a in alertes] == [(IP_A, 5)]

    def test_seuil_un_un_seul_echec_suffit(self):
        alertes = detecter(rafale(timedelta(0)), seuil=1)

        assert [(str(a.ip), a.pic, a.total) for a in alertes] == [(IP_A, 1, 1)]


class TestFenetre:
    def test_cinq_echecs_en_exactement_dix_minutes_borne_incluse(self):
        # Entrée volontairement non triée.
        evenements = rafale(*minutes(10, 0, 7, 2, 5))

        assert len(detecter(evenements)) == 1

    def test_borne_incluse_a_la_microseconde_pres(self):
        # Écart exact de FENETRE entre deux instants non ronds.
        une_us = timedelta(microseconds=1)
        decalages = [une_us, *minutes(2, 5, 7), FENETRE + une_us]

        alertes = detecter(rafale(*decalages))

        assert [a.fin_pic - a.debut_pic for a in alertes] == [FENETRE]

    def test_cinq_echecs_etales_sur_plus_de_dix_minutes_ignores(self):
        decalages = minutes(0, 2, 5, 7) + [FENETRE + timedelta(microseconds=1)]

        assert detecter(rafale(*decalages)) == ()

    def test_fenetre_glissante_et_non_fixe(self):
        # 5 échecs entre 08:08 et 08:16 : aucun créneau fixe de 10 min ne les
        # contient tous, une fenêtre glissante si.
        assert len(detecter(rafale(*minutes(8, 9, 11, 14, 16)))) == 1

    def test_echecs_reguliers_jamais_cinq_en_dix_minutes(self):
        # Un échec toutes les 3 minutes pendant une heure : 4 au plus par fenêtre.
        assert detecter(rafale(*minutes(*range(0, 60, 3)))) == ()


class TestPic:
    def test_pic_bornes_et_total_sur_deux_rafales(self):
        evenements = rafale(*minutes(0, 1, 2, 3, 4)) + rafale(
            *minutes(60, 61, 62, 63, 64, 65)
        )

        (alerte,) = detecter(evenements)

        assert (alerte.pic, alerte.total) == (6, 11)
        assert alerte.debut_pic == T0 + timedelta(minutes=60)
        assert alerte.fin_pic == T0 + timedelta(minutes=65)

    def test_a_egalite_la_premiere_rafale_est_retenue(self):
        evenements = rafale(*minutes(0, 1, 2, 3, 4)) + rafale(
            *minutes(60, 61, 62, 63, 64)
        )

        (alerte,) = detecter(evenements)

        assert (alerte.debut_pic, alerte.fin_pic) == (
            T0,
            T0 + timedelta(minutes=4),
        )


class TestComptes:
    def test_comptes_distincts_et_tries(self):
        comptes = ["root", "admin", "", "root", "admin", "invite"]
        evenements = [
            ev(timedelta(minutes=i), compte=c) for i, c in enumerate(comptes)
        ]

        (alerte,) = detecter(evenements)

        assert alerte.comptes == ("", "admin", "invite", "root")


class TestOrdre:
    def test_pic_decroissant_puis_ip_ipv4_avant_ipv6(self):
        cinq = minutes(0, 1, 2, 3, 4)
        evenements = (
            rafale(*cinq, ip=IP_B)
            + rafale(*minutes(0, 1, 2, 3, 4, 5), ip="::1")
            + rafale(*cinq, ip=IP_A)
            + rafale(*cinq, ip="127.0.0.1")
        )

        alertes = detecter(evenements)

        assert [str(a.ip) for a in alertes] == [
            "::1",
            "127.0.0.1",
            IP_A,
            IP_B,
        ]

    def test_a_pic_egal_ipv4_avant_ipv6(self):
        cinq = minutes(0, 1, 2, 3, 4)
        evenements = rafale(*cinq, ip="::1") + rafale(*cinq, ip="127.0.0.1")

        alertes = detecter(evenements)

        assert [str(a.ip) for a in alertes] == ["127.0.0.1", "::1"]

    def test_a_pic_egal_ordre_numerique_et_non_textuel(self):
        # En texte, "192.0.2.10" < "192.0.2.9" ; en valeur, c'est l'inverse.
        cinq = minutes(0, 1, 2, 3, 4)
        evenements = rafale(*cinq, ip="192.0.2.10") + rafale(*cinq, ip="192.0.2.9")

        alertes = detecter(evenements)

        assert [str(a.ip) for a in alertes] == ["192.0.2.9", "192.0.2.10"]


class TestParametres:
    def test_seuil_et_fenetre_personnalises(self):
        evenements = rafale(*minutes(0, 0.5, 1))

        alertes = detecter(evenements, seuil=3, fenetre=timedelta(minutes=1))

        assert [a.pic for a in alertes] == [3]

    def test_fenetre_egale_a_la_marge_de_calcul_acceptee(self):
        assert detecter(rafale(*minutes(0)), fenetre=MARGE_CALCUL) == ()

    @pytest.mark.parametrize(
        "fenetre",
        [
            MARGE_CALCUL + timedelta(microseconds=1),
            timedelta(0),
            timedelta(minutes=-10),
        ],
        ids=["au-dela-de-la-marge", "nulle", "negative"],
    )
    def test_fenetre_hors_limites_refusee(self, fenetre):
        with pytest.raises(ValueError, match="fenêtre"):
            detecter([], fenetre=fenetre)

    @pytest.mark.parametrize("seuil", [0, -1])
    def test_seuil_inferieur_a_un_refuse(self, seuil):
        with pytest.raises(ValueError, match="seuil"):
            detecter([], seuil=seuil)

    def test_valeurs_par_defaut(self):
        assert (SEUIL_ECHECS, FENETRE) == (5, timedelta(minutes=10))


class TestCasParticuliers:
    def test_aucun_evenement_aucune_alerte(self):
        assert detecter([]) == ()

    def test_fuseaux_melanges_compares_en_temps_absolu(self):
        # 08:0x+01:00 et 07:0xZ sont les mêmes instants : 5 échecs en 4 min.
        # Comparées en heure murale, ces dates seraient à une heure d'écart.
        utc = timezone.utc
        horodatages = [
            T0,
            T0 + timedelta(minutes=1),
            datetime(2026, 11, 3, 7, 2, tzinfo=utc),
            datetime(2026, 11, 3, 7, 3, tzinfo=utc),
            datetime(2026, 11, 3, 7, 4, tzinfo=utc),
        ]
        evenements = [
            Evenement(horodatage=h, compte="admin", ip=ip_address(IP_A))
            for h in horodatages
        ]

        (alerte,) = detecter(evenements)

        assert alerte.pic == 5
        assert alerte.fin_pic - alerte.debut_pic == timedelta(minutes=4)

    def test_echecs_simultanes_comptes_chacun(self):
        assert [a.pic for a in detecter(rafale(*[timedelta(0)] * 5))] == [5]

    def test_adresse_locale_comptee_et_marquee(self):
        evenements = rafale(*minutes(0, 1, 2, 3, 4), ip="::1") + rafale(
            *minutes(0, 1, 2, 3, 4)
        )

        alertes = detecter(evenements)

        assert [(str(a.ip), a.est_locale) for a in alertes] == [
            (IP_A, False),
            ("::1", True),
        ]

    def test_alerte_non_modifiable(self):
        (alerte,) = detecter(rafale(*minutes(0, 1, 2, 3, 4)))

        assert isinstance(alerte, Alerte)
        with pytest.raises(AttributeError):
            alerte.pic = 0  # type: ignore[misc]


class TestIntegrationLecture:
    def test_export_d_attaque(self, donnees):
        lecture = lire_export(donnees / "export_attaque.csv")

        alertes = detecter(lecture.evenements)

        assert [(str(a.ip), a.pic, a.total, a.est_locale) for a in alertes] == [
            ("203.0.113.66", 6, 6, False),
            ("::1", 5, 5, True),
        ]
        assert alertes[0].comptes == (
            "admin",
            "administrateur",
            "invite",
            "root",
            "sauvegarde",
        )
        assert [r.numero for r in lecture.rejets] == [16]
