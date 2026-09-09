"""NLP-to-SQL module (importable version)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from analytics._nlp_core import ask, run_query, EXAMPLE_QUERIES

__all__ = ["ask", "run_query", "EXAMPLE_QUERIES"]
