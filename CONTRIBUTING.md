# Contributing to PredictiveAttackPath

Thank you for your interest in contributing! Here's how to get started.

## Development Setup

1. Clone the repository
2. Install backend dependencies: `cd backend && pip install -r requirements.txt`
3. Install the plugin in Sublime Text (see README)
4. Run the test suite: `cd backend && python -m pytest test_engine.py -v`

## Adding New Regex Patterns

The regex pattern library is in `backend/regex_patterns.py`. To add patterns for a new technique:

```python
_register("T1234", "Technique Name", "tactic-slug", [
    r"pattern_one",
    r"pattern_two",
], 0.85)
```

After adding patterns, run the validator: `cd backend && python validate.py`

## Pull Request Process

1. Fork the repo and create a feature branch
2. Make your changes
3. Run the full test suite
4. Update documentation if needed
5. Submit a PR with a clear description of the changes

## Code Style

- Backend code: Python 3.10+ with type hints
- Plugin code: Python 3.8 compatible (Sublime Text constraint)
- Use `from __future__ import annotations` where appropriate

## Reporting Issues

Please include:
- Sublime Text version and OS
- Python version (`python --version`)
- The Sublime console output (`View > Show Console`)
- Steps to reproduce
