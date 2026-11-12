from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import pytest

from ego.detection import Alerte
from ego.lecture import LIBELLE_SANS_IP, SANS_IP, SansIP
from ego.registre import PLAFOND_REGISTRE, Registre, collecter_registre

T0 = datetime(2026, 11, 3, 8, 0, tzinfo=timezone(timedelta(hours=1)))


def alerte(ip: str | SansIP, *comptes: str) -> Alerte:
    """Alerte dont seuls l'origine et les comptes, dans l'ordre donné, comptent ici."""
    origine = ip_address(ip) if isinstance(ip, str) else ip
    return Alerte(
        ip=origine, pic=5, debut_pic=T0, fin_pic=T0, total=5, comptes=comptes
    )


class TestOrigineSansIP:
    def test_libelle_inscrit_au_registre(self):
        registre = collecter_registre((alerte(SANS_IP, "bob"),))

        assert registre == Registre((LIBELLE_SANS_IP, "bob"), 2, 0)

    def test_compte_nomme_tiret_distinct_de_l_origine(self):
        # L'origine s'affiche « (local, sans IP) », jamais « - » : un compte
        # nommé « - » ne peut pas se confondre avec elle.
        registre = collecter_registre((alerte(SANS_IP, "-"),))

        assert registre.noms == (LIBELLE_SANS_IP, "-")

    @pytest.mark.parametrize("compte", [LIBELLE_SANS_IP, "(LOCAL, SANS IP)"])
    def test_compte_nomme_comme_le_libelle_jamais_absorbe(self, compte):
        # Origine d'abord, puis compte : deux entrées.
        apres = collecter_registre((alerte(SANS_IP, compte),))
        # Compte d'abord (autre alerte), puis origine : deux entrées aussi.
        avant = collecter_registre((alerte("192.0.2.1", compte), alerte(SANS_IP)))

        assert apres == Registre((LIBELLE_SANS_IP, compte), 2, 0)
        assert avant == Registre(("192.0.2.1", compte, LIBELLE_SANS_IP), 3, 0)

    def test_origine_comptee_une_fois(self):
        registre = collecter_registre((alerte(SANS_IP, "a"), alerte(SANS_IP, "b")))

        assert registre.noms == (LIBELLE_SANS_IP, "a", "b")


def refus(plafond: object, alertes: tuple[Alerte, ...] = ()) -> str:
    """Message de la ValueError levée ; toute autre issue échoue par assertion."""
    try:
        collecter_registre(alertes, plafond)  # type: ignore[arg-type]
    except Exception as erreur:  # noqa: BLE001 - le type est vérifié juste après
        assert isinstance(erreur, ValueError), f"{type(erreur).__name__}: {erreur}"
        return str(erreur)
    raise AssertionError("aucune ValueError levée")


class TestOrdre:
    def test_ip_puis_comptes_alerte_par_alerte(self):
        alertes = (
            alerte("192.0.2.1", "bob", "alice"),
            alerte("203.0.113.7", "carol"),
        )

        registre = collecter_registre(alertes)

        assert registre == Registre(
            noms=("192.0.2.1", "bob", "alice", "203.0.113.7", "carol"),
            total=5,
            masques=0,
        )

    def test_aucune_alerte(self):
        assert collecter_registre(()) == Registre((), 0, 0)

    def test_alerte_sans_compte(self):
        assert collecter_registre((alerte("::1"),)) == Registre(("::1",), 1, 0)


class TestDedoublonnage:
    def test_doublon_exact_garde_la_premiere_apparition(self):
        alertes = (
            alerte("192.0.2.1", "admin", "bob"),
            alerte("192.0.2.2", "bob", "admin"),
        )

        registre = collecter_registre(alertes)

        assert registre.noms == ("192.0.2.1", "admin", "bob", "192.0.2.2")
        assert registre.total == 4

    def test_doublon_de_casse_garde_la_premiere_graphie(self):
        alertes = (
            alerte("192.0.2.1", "Admin"),
            alerte("192.0.2.2", "ADMIN", "admin"),
        )

        registre = collecter_registre(alertes)

        assert registre == Registre(("192.0.2.1", "Admin", "192.0.2.2"), 3, 0)

    def test_eszett_distinct_de_ss_comme_sous_windows(self):
        # Windows compare les comptes caractère par caractère : « Straße » et
        # « STRASSE » sont deux comptes. casefold() les confondrait (ß -> ss).
        alertes = (alerte("192.0.2.1", "Straße", "STRASSE"),)

        assert collecter_registre(alertes) == Registre(
            ("192.0.2.1", "Straße", "STRASSE"), 3, 0
        )

    def test_ip_identique_a_un_compte_comptee_une_fois(self):
        alertes = (
            alerte("192.0.2.1", "bob"),
            alerte("192.0.2.2", "192.0.2.1"),
        )

        registre = collecter_registre(alertes)

        assert registre == Registre(("192.0.2.1", "bob", "192.0.2.2"), 3, 0)

    def test_compte_avant_l_ip_qui_lui_est_identique(self):
        # Le compte est vu le premier : c'est sa graphie qui reste.
        alertes = (
            alerte("192.0.2.1", "2001:DB8::1"),
            alerte("2001:db8::1", "bob"),
        )

        registre = collecter_registre(alertes)

        assert registre.noms == ("192.0.2.1", "2001:DB8::1", "bob")


class TestPlafond:
    def test_valeur_par_defaut(self):
        assert PLAFOND_REGISTRE == 50

    def test_plafond_par_defaut_applique(self):
        comptes = tuple(f"compte{n:02}" for n in range(60))

        registre = collecter_registre((alerte("192.0.2.1", *comptes),))

        assert registre.noms == ("192.0.2.1", *comptes[:49])
        assert (registre.total, registre.masques) == (61, 11)

    def test_plafond_atteint_total_et_masques(self):
        alertes = (
            alerte("192.0.2.1", "a", "b"),
            alerte("192.0.2.2", "c", "d"),
        )

        registre = collecter_registre(alertes, plafond=4)

        assert registre == Registre(("192.0.2.1", "a", "b", "192.0.2.2"), 6, 2)

    def test_plafond_apres_dedoublonnage(self):
        # Les doublons ne prennent pas de place sous le plafond.
        alertes = (alerte("192.0.2.1", "A", "a", "b", "B", "c"),)

        registre = collecter_registre(alertes, plafond=3)

        assert registre == Registre(("192.0.2.1", "A", "b"), 4, 1)

    def test_plafond_egal_au_total(self):
        alertes = (alerte("192.0.2.1", "a", "b"),)

        assert collecter_registre(alertes, plafond=3) == Registre(
            ("192.0.2.1", "a", "b"), 3, 0
        )

    def test_plafond_un(self):
        alertes = (alerte("192.0.2.1", "a", "b"),)

        assert collecter_registre(alertes, plafond=1) == Registre(("192.0.2.1",), 3, 2)

    @pytest.mark.parametrize("plafond", [0, -1, True, False, 2.5, "3", None])
    def test_plafond_invalide_refuse(self, plafond):
        message = refus(plafond, (alerte("192.0.2.1", "bob"),))

        assert message == f"plafond invalide : {plafond!r} (entier >= 1 attendu)"

    def test_plafond_verifie_meme_sans_alerte(self):
        assert refus(0).startswith("plafond invalide : 0")


class TestNomsBruts:
    def test_controles_et_bidi_conserves_sans_plantage(self):
        # Neutralisation au rendu, pas ici : le registre garde les noms tels quels.
        comptes = ("ad\x00min", "\u202eevil", "a\r\nb", "\x1b[31mrouge", "\ud800")
        alertes = (alerte("192.0.2.1", *comptes),)

        registre = collecter_registre(alertes)

        assert registre.noms == ("192.0.2.1", *comptes)

    def test_nom_long_non_tronque(self):
        long = "x" * 500

        registre = collecter_registre((alerte("192.0.2.1", long),))

        assert registre.noms == ("192.0.2.1", long)

    def test_nom_vide_garde_tel_quel(self):
        # « (sans nom) » est une affaire de rendu.
        assert collecter_registre((alerte("192.0.2.1", ""),)).noms == ("192.0.2.1", "")


class TestRegistre:
    def test_fige(self):
        registre = collecter_registre((alerte("192.0.2.1", "bob"),))

        with pytest.raises(FrozenInstanceError):
            registre.total = 0  # type: ignore[misc]
