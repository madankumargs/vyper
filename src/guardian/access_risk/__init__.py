"""Provider-neutral, evidence-based SaaS access risk analysis."""

from .engine import analyze
from .loader import load_input, validate_input

__all__ = ["analyze", "load_input", "validate_input"]
