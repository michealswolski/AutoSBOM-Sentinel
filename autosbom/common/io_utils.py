"""Shared, defensive file-loading helpers.

Every JSON/YAML file this tool reads was produced by an external process
(a scanner, a human-edited context file, a previous run's own output) —
none of it is trusted to be well-formed. These helpers turn a raw parse
failure into a message that names the offending file, instead of a bare
JSONDecodeError pointing at a line/column with no file context.
"""
from __future__ import annotations

import json
from pathlib import Path


def load_json(path: str | Path) -> dict | list:
    """Read and parse a JSON file, raising a clear, file-named error on failure.

    Raises FileNotFoundError (Python's default message already names the
    path) if the file doesn't exist, or ValueError if it exists but isn't
    valid JSON.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p}: not valid JSON ({exc.msg} at line {exc.lineno}, "
                         f"column {exc.colno})") from exc


def load_yaml_or_json(path: str | Path) -> dict | list:
    """Load a file as YAML if .yaml/.yml, otherwise as JSON. Same error style."""
    p = Path(path)
    if p.suffix.lower() not in (".yaml", ".yml"):
        return load_json(p)
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            f"{p} is YAML but PyYAML is not installed; either "
            f"`pip install PyYAML` or provide the file as JSON instead"
        ) from exc
    text = p.read_text(encoding="utf-8")
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{p}: not valid YAML ({exc})") from exc
