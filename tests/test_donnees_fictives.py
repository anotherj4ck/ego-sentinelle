"""Test de garde : aucune adresse IP réelle dans les exports d'exemple.

La colonne IP de chaque CSV de tests/donnees/ ne doit contenir que des adresses
des plages de documentation RFC 5737 192.0.2.0/24 et 203.0.113.0/24.
Seules exceptions : les adresses de bouclage exactes ::1 et 127.0.0.1.
Une IPv4 mappée en IPv6 (::ffff:a.b.c.d) est jugée sur son IPv4.
Les valeurs qui ne sont pas des IP (lignes volontairement malformées) sont ignorées.
"""

import csv
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from pathlib import Path

import pytest

DOSSIER_DONNEES = Path(__file__).parent / "donnees"
PLAGES_AUTORISEES = (ip_network("192.0.2.0/24"), ip_network("203.0.113.0/24"))
EXCEPTIONS_AUTORISEES = frozenset({ip_address("::1"), ip_address("127.0.0.1")})
EXPORTS = sorted(DOSSIER_DONNEES.glob("*.csv"))


def ips_de_l_export(chemin: Path) -> Iterator[IPv4Address | IPv6Address]:
    with open(chemin, encoding="utf-8-sig", newline="") as flux:
        for ligne in csv.DictReader(flux):
            valeur = (ligne.get("IP") or "").strip()
            try:
                yield ip_address(valeur)
            except ValueError:
                continue


def est_autorisee(adresse: IPv4Address | IPv6Address) -> bool:
    if isinstance(adresse, IPv6Address) and adresse.ipv4_mapped is not None:
        adresse = adresse.ipv4_mapped
    if adresse in EXCEPTIONS_AUTORISEES:
        return True
    return any(adresse in plage for plage in PLAGES_AUTORISEES)


def test_des_exports_sont_surveilles():
    noms = {p.name for p in EXPORTS}

    assert {"export_valide.csv", "export_malforme.csv"} <= noms


@pytest.mark.parametrize("export", EXPORTS, ids=lambda p: p.name)
def test_uniquement_des_ip_de_documentation(export: Path):
    adresses = list(ips_de_l_export(export))

    interdites = sorted({str(a) for a in adresses if not est_autorisee(a)})

    assert adresses, f"aucune IP lue dans {export.name} : le garde serait vide"
    assert interdites == [], f"IP hors plages de documentation dans {export.name}"


@pytest.mark.parametrize(
    ("adresse", "attendu"),
    [
        ("192.0.2.0", True),
        ("203.0.113.255", True),
        ("::1", True),
        ("127.0.0.1", True),
        ("::ffff:192.0.2.10", True),
        ("192.0.3.0", False),  # juste après la plage
        ("203.0.112.255", False),  # juste avant la plage
        ("198.51.100.1", False),  # documentation aussi, mais non retenue ici
        ("127.0.0.2", False),  # bouclage, mais pas l'exception exacte
        ("8.8.8.8", False),  # adresse publique réelle
    ],
)
def test_regle_de_garde(adresse: str, attendu: bool):
    assert est_autorisee(ip_address(adresse)) is attendu
