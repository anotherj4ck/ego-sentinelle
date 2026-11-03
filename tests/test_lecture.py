import csv
import io
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, ip_address

import pytest

from ego.lecture import (
    ErreurFormat,
    Evenement,
    LigneRejetee,
    Raison,
    analyser_csv,
    lire_export,
)

EN_TETE = '"Date","Compte","IP"'
DATE_OK = "2026-11-03T08:12:45.1234567+01:00"
PLUS_UNE_HEURE = timezone(timedelta(hours=1))


def analyser(*lignes: str, en_tete: str = EN_TETE):
    """Analyse un CSV construit en mémoire : en-tête puis une ligne par argument."""
    return analyser_csv(io.StringIO("\n".join((en_tete, *lignes)) + "\n", newline=""))


def ligne(date: str = DATE_OK, compte: str = "alice", ip: str = "192.0.2.10") -> str:
    return f'"{date}","{compte}","{ip}"'


@pytest.fixture(params=[None, 300_000], ids=["limite-par-defaut", "limite-relevee"])
def limite_champ_csv(request) -> int:
    """Limite de taille de champ du module csv (état global), restaurée ensuite."""
    precedente = csv.field_size_limit()
    if request.param is not None:
        csv.field_size_limit(request.param)
    yield csv.field_size_limit()
    csv.field_size_limit(precedente)


def seul_rejet(resultat) -> LigneRejetee:
    assert resultat.evenements == ()
    assert len(resultat.rejets) == 1
    return resultat.rejets[0]


class TestExportValide:
    def test_lit_tous_les_evenements_sans_rejet(self, donnees):
        resultat = lire_export(donnees / "export_valide.csv")

        assert len(resultat.evenements) == 6
        assert resultat.rejets == ()

    def test_premier_evenement_complet(self, donnees):
        premier = lire_export(donnees / "export_valide.csv").evenements[0]

        assert premier == Evenement(
            horodatage=datetime(2026, 11, 3, 8, 12, 45, 123456, tzinfo=PLUS_UNE_HEURE),
            compte="administrateur",
            ip=ip_address("192.0.2.10"),
        )

    def test_compte_vide_accepte(self, donnees):
        dernier = lire_export(donnees / "export_valide.csv").evenements[-1]

        assert dernier.compte == ""
        assert dernier.ip == ip_address("203.0.113.7")

    def test_adresses_locales_marquees(self, donnees):
        evenements = lire_export(donnees / "export_valide.csv").evenements

        locales = [e.ip for e in evenements if e.est_locale]

        assert locales == [ip_address("::1"), ip_address("127.0.0.1")]


class TestAdressesLocales:
    @pytest.mark.parametrize("ip", ["::1", "127.0.0.1", "::ffff:127.0.0.1"])
    def test_bouclage_valide_et_locale(self, ip):
        evenement = analyser(ligne(ip=ip)).evenements[0]

        assert evenement.est_locale is True

    @pytest.mark.parametrize("ip", ["192.0.2.10", "203.0.113.7"])
    def test_adresse_distante_non_locale(self, ip):
        evenement = analyser(ligne(ip=ip)).evenements[0]

        assert evenement.est_locale is False

    def test_ipv4_mappee_en_ipv6_normalisee_en_ipv4(self):
        evenement = analyser(ligne(ip="::ffff:192.0.2.10")).evenements[0]

        assert evenement.ip == IPv4Address("192.0.2.10")


class TestDates:
    def test_sept_decimales_tronquees_a_la_microseconde(self):
        resultat = analyser(ligne(date="2026-11-03T08:12:45.1234567+01:00"))

        assert resultat.evenements[0].horodatage.microsecond == 123456

    def test_suffixe_z_accepte_comme_utc(self):
        evenement = analyser(ligne(date="2026-11-03T07:12:45Z")).evenements[0]

        assert evenement.horodatage.utcoffset() == timedelta(0)

    def test_date_sans_fuseau_rejetee(self):
        rejet = seul_rejet(analyser(ligne(date="2026-11-03T08:12:45.1234567")))

        assert rejet.raison is Raison.DATE_SANS_FUSEAU
        assert rejet.detail == "2026-11-03T08:12:45.1234567"

    @pytest.mark.parametrize(
        "date", ["03/11/2026 08:12:49", "", "demain", "2026-13-01T00:00:00+01:00"]
    )
    def test_date_illisible_rejetee(self, date):
        rejet = seul_rejet(analyser(ligne(date=date)))

        assert rejet.raison is Raison.DATE_ILLISIBLE

    @pytest.mark.parametrize(
        "date",
        [
            "20261103T081245+01",  # format compact
            "2026-11-03T08+01:00",  # heure seule
            "2026-W44-2T08:12:45+01:00",  # date par semaine
            "2026-11-03T08:12:45,5+01:00",  # virgule décimale
            "2026-11-03 08:12:45+01:00",  # espace au lieu de T
            "2026-11-03T08:12:45+00:00:30",  # décalage avec secondes
            "2026-11-03T24:00:00+01:00",  # 24 h = lendemain
            "2026-11-03T08:12:45.12345678+01:00",  # 8 décimales
            "2026-11-03T08:12:45z",  # z minuscule
        ],
    )
    def test_seul_le_format_o_est_accepte(self, date):
        rejet = seul_rejet(analyser(ligne(date=date)))

        assert rejet.raison is Raison.DATE_ILLISIBLE

    @pytest.mark.parametrize(
        "date",
        [
            "0001-01-01T00:00:00+23:59",  # conversion UTC impossible
            "9999-12-31T23:59:59-23:59",  # conversion UTC impossible
            "0001-01-01T00:00:00Z",  # date - fenêtre impossible
            "9999-12-31T23:55:00Z",  # date + 10 min impossible
            # Calculables en UTC, mais pas dans leur fuseau d'origine :
            "9999-12-31T13:00:00+14:00",  # date + marge impossible
            "0001-01-01T10:00:00-14:00",  # date - marge impossible
        ],
    )
    def test_date_aux_limites_du_calendrier_rejetee(self, date):
        rejet = seul_rejet(analyser(ligne(date=date)))

        assert rejet.raison is Raison.DATE_ILLISIBLE


class TestIP:
    @pytest.mark.parametrize("ip", ["-", "", "   "])
    def test_ip_absente_rejetee(self, ip):
        rejet = seul_rejet(analyser(ligne(ip=ip)))

        assert rejet.raison is Raison.IP_ABSENTE

    @pytest.mark.parametrize("ip", ["192.0.2.999", "pas-une-ip", "192.0.2"])
    def test_ip_invalide_rejetee(self, ip):
        rejet = seul_rejet(analyser(ligne(ip=ip)))

        assert rejet.raison is Raison.IP_INVALIDE
        assert rejet.detail == ip

    @pytest.mark.parametrize("ip", ["::1%12", "::ffff:192.0.2.10%3"])
    def test_ipv6_avec_identifiant_de_zone_rejetee(self, ip):
        rejet = seul_rejet(analyser(ligne(ip=ip)))

        assert rejet.raison is Raison.IP_INVALIDE
        assert rejet.detail == ip

    def test_espaces_autour_des_valeurs_ignores(self):
        evenement = analyser(f'" {DATE_OK} "," alice "," 192.0.2.10 "').evenements[0]

        assert evenement.compte == "alice"
        assert evenement.ip == ip_address("192.0.2.10")


class TestLignesMalformees:
    def test_chaque_ligne_rejetee_avec_sa_raison(self, donnees):
        resultat = lire_export(donnees / "export_malforme.csv")

        assert [(r.numero, r.raison) for r in resultat.rejets] == [
            (3, Raison.IP_ABSENTE),
            (4, Raison.IP_ABSENTE),
            (5, Raison.DATE_SANS_FUSEAU),
            (6, Raison.DATE_ILLISIBLE),
            (7, Raison.IP_INVALIDE),
            (8, Raison.COLONNES),
            (9, Raison.COLONNES),
            (11, Raison.IP_INVALIDE),
        ]

    def test_lignes_valides_conservees(self, donnees):
        resultat = lire_export(donnees / "export_malforme.csv")

        assert [e.compte for e in resultat.evenements] == ["alice", "ines"]

    def test_numero_de_debut_pour_un_champ_sur_plusieurs_lignes(self):
        # Ligne 2-3 : compte sur deux lignes et IP absente ; ligne 4 : IP absente.
        resultat = analyser(f'"{DATE_OK}","a\nb","-"', ligne(ip="-"))

        assert [r.numero for r in resultat.rejets] == [2, 4]

    def test_ligne_vide_ignoree_sans_rejet(self):
        resultat = analyser(ligne(), "", ligne(compte="bob"))

        assert [e.compte for e in resultat.evenements] == ["alice", "bob"]
        assert resultat.rejets == ()

    def test_champ_manquant_rejete(self):
        rejet = seul_rejet(analyser(f'"{DATE_OK}","alice"'))

        assert rejet.raison is Raison.COLONNES
        assert rejet.detail == "2 champs au lieu de 3"

    def test_champ_en_trop_rejete(self):
        rejet = seul_rejet(analyser(ligne() + ',"en trop"'))

        assert rejet.raison is Raison.COLONNES
        assert rejet.detail == "4 champs au lieu de 3"

    def test_champ_trop_long_rejete_et_lecture_poursuivie(self, limite_champ_csv):
        resultat = analyser("x" * (limite_champ_csv + 1), ligne(compte="bob"))

        rejets = [(r.numero, r.raison) for r in resultat.rejets]
        assert rejets == [(2, Raison.CSV_ILLISIBLE)]
        assert [e.compte for e in resultat.evenements] == ["bob"]

    def test_detail_long_tronque_a_100_caracteres(self):
        rejet = seul_rejet(analyser(ligne(date="9" * 5000)))

        assert rejet.detail == "9" * 99 + "…"

    def test_detail_de_100_caracteres_conserve_tel_quel(self):
        rejet = seul_rejet(analyser(ligne(ip="9" * 100)))

        assert rejet.detail == "9" * 100

    def test_octet_nul_dans_ip_rejete(self):
        rejet = seul_rejet(analyser(ligne(ip="192.0.2.10\x00")))

        assert rejet.raison is Raison.IP_INVALIDE


class TestEnTete:
    def test_colonnes_lues_par_nom_quel_que_soit_l_ordre(self):
        resultat = analyser(
            f'"192.0.2.10","alice","{DATE_OK}"', en_tete='"IP","Compte","Date"'
        )

        assert resultat.evenements[0].compte == "alice"
        assert resultat.evenements[0].ip == ip_address("192.0.2.10")

    def test_colonne_supplementaire_ignoree(self):
        resultat = analyser(ligne() + ',"4625"', en_tete=EN_TETE + ',"Id"')

        assert len(resultat.evenements) == 1
        assert resultat.rejets == ()

    def test_colonne_manquante_erreur_explicite(self):
        with pytest.raises(ErreurFormat, match="IP"):
            analyser('"2026-11-03T08:12:45+01:00","alice"', en_tete='"Date","Compte"')

    def test_en_tete_absent_erreur(self):
        with pytest.raises(ErreurFormat, match="Date"):
            analyser(ligne(), en_tete=ligne(compte="bob"))

    def test_fichier_vide_erreur(self):
        with pytest.raises(ErreurFormat, match="vide"):
            analyser_csv(io.StringIO("", newline=""))

    def test_en_tete_illisible_erreur(self, limite_champ_csv):
        with pytest.raises(ErreurFormat, match="illisible"):
            analyser(ligne(), en_tete="x" * (limite_champ_csv + 1))

    def test_en_tete_seul_donne_un_resultat_vide(self):
        resultat = analyser()

        assert resultat.evenements == ()
        assert resultat.rejets == ()


class TestEncodage:
    def test_bom_et_crlf_de_powershell_5(self, ecrire_export):
        contenu = "\r\n".join((EN_TETE, ligne(), "")).encode("utf-8")
        chemin = ecrire_export(b"\xef\xbb\xbf" + contenu)

        resultat = lire_export(chemin)

        assert len(resultat.evenements) == 1
        assert resultat.rejets == ()

    def test_octet_invalide_dans_le_compte_ne_plante_pas(self, ecrire_export):
        contenu = f'{EN_TETE}\n"{DATE_OK}","al\xffice","192.0.2.10"\n'.encode("latin-1")

        resultat = lire_export(ecrire_export(contenu))

        assert resultat.evenements[0].compte == "al�ice"

    def test_octet_invalide_dans_l_ip_rejete(self, ecrire_export):
        contenu = f'{EN_TETE}\n"{DATE_OK}","alice","192.0.2.1\xff"\n'.encode("latin-1")

        rejet = seul_rejet(lire_export(ecrire_export(contenu)))

        assert rejet.raison is Raison.IP_INVALIDE


class TestImmuabilite:
    def test_evenement_non_modifiable(self):
        evenement = analyser(ligne()).evenements[0]

        with pytest.raises(FrozenInstanceError):
            evenement.compte = "mallory"  # type: ignore[misc]

    def test_resultat_en_tuples(self):
        resultat = analyser(ligne(), ligne(ip="-"))

        assert isinstance(resultat.evenements, tuple)
        assert isinstance(resultat.rejets, tuple)
