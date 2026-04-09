"""conftest.py — shared test fixtures."""
import sys
import os

# Ensure backend imports work from tests/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
