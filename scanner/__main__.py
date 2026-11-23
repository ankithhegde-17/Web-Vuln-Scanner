"""Allows running the scanner as a module: `python -m scanner <url> ...`."""

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
