"""Test de garde : aucune adresse IP réelle dans les tests.

Toute chaîne qui ressemble à une adresse IP valide dans tests/ (code et exports CSV)
doit appartenir aux plages de documentation RFC 5737 192.0.2.0/24 ou 203.0.113.0/24.
Seules exceptions : les adresses de bouclage exactes ::1 et 127.0.0.1.
Une IPv4 mappée en IPv6 (::ffff:a.b.c.d) est jugée sur son IPv4.

Attention : une découpe Python avec un pas (deux « : » collés suivis d'un chiffre)
ressemble à une IPv6 et ferait échouer ce test ; l'écrire autrement.
"""

import re
from ipaddress import IPv6Address, ip_address, ip_network
from pathlib import Path

import pytest

DOSSIER_TESTS = Path(__file__).parent
PLAGES_AUTORISEES = (ip_network("192.0.2.0/24"), ip_network("203.0.113.0/24"))
EXCEPTIONS_AUTORISEES = frozenset({ip_address("::1"), ip_address("127.0.0.1")})
CANDIDAT_IP = re.compile(r"[0-9A-Fa-f]*(?:[:.][0-9A-Fa-f]*)+")


def adresses_dans(texte: str):
    for candidat in CANDIDAT_IP.findall(texte):
        try:
            yield ip_address(candidat)
        except ValueError:
            continue


def est_autorisee(adresse) -> bool:
    if isinstance(adresse, IPv6Address) and adresse.ipv4_mapped is not None:
        adresse = adresse.ipv4_mapped
    if adresse in EXCEPTIONS_AUTORISEES:
        return True
    return any(adresse in plage for plage in PLAGES_AUTORISEES)


FICHIERS_SURVEILLES = sorted(
    p for motif in ("**/*.py", "**/*.csv") for p in DOSSIER_TESTS.glob(motif)
)


def test_des_fichiers_sont_surveilles():
    noms = {p.name for p in FICHIERS_SURVEILLES}

    assert {"export_valide.csv", "export_malforme.csv", "test_lecture.py"} <= noms


@pytest.mark.parametrize("fichier", FICHIERS_SURVEILLES, ids=lambda p: p.name)
def test_uniquement_des_ip_de_documentation(fichier: Path):
    texte = fichier.read_text(encoding="utf-8")

    interdites = sorted({str(a) for a in adresses_dans(texte) if not est_autorisee(a)})

    assert interdites == [], f"IP hors plages de documentation dans {fichier.name}"


# Les contre-exemples sont calculés, jamais écrits en clair : sinon ce fichier
# échouerait à son propre contrôle.
@pytest.mark.parametrize(
    ("adresse", "attendu"),
    [
        (ip_address("192.0.2.0"), True),
        (ip_address("203.0.113.255"), True),
        (ip_address("::1"), True),
        (ip_address("127.0.0.1"), True),
        (ip_address("::ffff:192.0.2.10"), True),
        (ip_address("192.0.2.255") + 1, False),  # juste après la plage
        (ip_address("203.0.113.0") - 1, False),  # juste avant la plage
        (ip_address("127.0.0.1") + 1, False),  # bouclage, mais pas l'exception exacte
        (ip_address(".".join(["8"] * 4)), False),  # adresse publique réelle
    ],
    ids=str,
)
def test_regle_de_garde(adresse, attendu: bool):
    assert est_autorisee(adresse) is attendu


def test_detection_des_candidats_dans_une_ligne_csv():
    texte = '"2026-11-03T08:12:45.1234567+01:00","alice","::ffff:192.0.2.10"'

    assert list(adresses_dans(texte)) == [ip_address("::ffff:192.0.2.10")]
