"""Moved to pybrws.tools.verify; installed, it runs as `pybrws verify`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pybrws.tools import verify as _tool  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(_tool.main())
sys.modules[__name__] = _tool
