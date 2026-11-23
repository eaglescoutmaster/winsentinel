"""winsentinel: defensive, read-only security scanner for Windows."""

__version__ = "0.3.0"


def main() -> int:
    from .cli import main as _main

    return _main()
