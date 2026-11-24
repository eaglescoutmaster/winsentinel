"""winsentinel: defensive, read-only security scanner for Windows, Linux and macOS."""

__version__ = "0.4.0"


def main() -> int:
    from .cli import main as _main

    return _main()
