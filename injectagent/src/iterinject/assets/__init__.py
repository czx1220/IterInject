"""Repository-bundled strategy assets, also included in installed packages."""
from pathlib import Path


def asset_root() -> Path:
    """Resolve assets relative to this package, independently of cwd or catalog."""
    return Path(__file__).resolve().parent
