"""Moved to pybrws.tools.catch_resumed; installed, it runs as `pybrws capture resumed`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pybrws.tools import catch_resumed as _tool  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(_tool.main())
sys.modules[__name__] = _tool
