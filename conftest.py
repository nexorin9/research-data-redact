"""让 pytest 能直接以 src/ 布局导入 research_redact 包（无需先 pip install -e .）。"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
