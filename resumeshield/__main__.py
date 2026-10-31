"""Allow `python -m resumeshield`."""
from __future__ import annotations

import sys

from resumeshield.cli import main

if __name__ == "__main__":
    sys.exit(main())
