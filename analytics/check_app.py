"""Compile-check app.py for syntax errors and import issues."""
import sys, ast, traceback
from pathlib import Path

src = Path("app.py").read_text(encoding="utf-8")

# 1. Syntax check
try:
    ast.parse(src)
    print("SYNTAX: OK")
except SyntaxError as e:
    print(f"SYNTAX ERROR at line {e.lineno}: {e.msg}")
    print(f"  >> {e.text}")
    sys.exit(1)

# 2. Count lines
print(f"LINES:  {len(src.splitlines())}")

# 3. Check for common blank-page causes
checks = [
    ("st.set_page_config",   "set_page_config" in src),
    ("def show(",            "def show(" in src),
    ("st.plotly_chart",      "st.plotly_chart" in src),
    ("st.session_state",     "session_state" in src),
    ("_CON = duckdb",        "_CON = duckdb" in src),
    ("date_input guard",     "isinstance(_dates" in src),
]
for label, result in checks:
    print(f"{'OK' if result else 'MISSING'}: {label}")

# 4. Find first page block
for i, line in enumerate(src.splitlines(), 1):
    if "Executive Summary" in line and "if page" in line:
        print(f"FIRST PAGE BLOCK: line {i}")
        break

print("\nDone.")
