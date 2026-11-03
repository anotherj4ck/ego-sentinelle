from pathlib import Path

import pytest

DOSSIER_DONNEES = Path(__file__).parent / "donnees"


@pytest.fixture
def donnees() -> Path:
    """Dossier des exports d'exemple fictifs."""
    return DOSSIER_DONNEES


@pytest.fixture
def ecrire_export(tmp_path):
    """Écrit des octets bruts dans un CSV temporaire (BOM, CRLF, octets invalides)."""

    def _ecrire(contenu: bytes, nom: str = "export.csv") -> Path:
        chemin = tmp_path / nom
        chemin.write_bytes(contenu)
        return chemin

    return _ecrire
