"""Open AI Grid Auth Service package."""

from pathlib import Path


def _version() -> str:
    try:
        return (Path(__file__).resolve().parents[1] / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "0.1.0"


__version__ = _version()
__author__ = "Open AI Grid Contributors"
