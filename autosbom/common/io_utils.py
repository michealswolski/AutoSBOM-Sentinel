"""Shared, defensive file-loading helpers.

Every JSON/YAML file this tool reads was produced by an external process
(a scanner, a human-edited context file, a previous run's own output) —
none of it is trusted to be well-formed. These helpers turn a raw parse
failure into a message that names the offending file, instead of a bare
JSONDecodeError pointing at a line/column with no file context.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _read_text(p: Path) -> str:
    """Read a file as UTF-8 text, naming the file on a decode failure too.

    A scanner output or hand-edited context file can turn out to be binary
    or non-UTF-8 (wrong file picked, truncated write, wrong encoding) —
    that should get the same file-named treatment as a JSON/YAML parse
    error, not a bare UnicodeDecodeError with no indication of which file
    among possibly several (e.g. --tool-output entries) caused it.
    """
    try:
        return p.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{p}: not valid UTF-8 text ({exc})") from exc


def load_json(path: str | Path) -> dict | list:
    """Read and parse a JSON file, raising a clear, file-named error on failure.

    Raises FileNotFoundError (Python's default message already names the
    path) if the file doesn't exist, or ValueError if it exists but isn't
    valid JSON (or isn't valid UTF-8 text at all).
    """
    p = Path(path)
    text = _read_text(p)
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
    text = _read_text(p)
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"{p}: not valid YAML ({exc})") from exc


def run_subprocess_or_raise(cmd: list[str], timeout: int, *,
                             error_label: str | None = None) -> str:
    """Run an external tool, raising RuntimeError naming it on failure/timeout.

    Shared by every call site that shells out to a scanner or extractor
    (syft, trivy, binwalk, ...) so the CalledProcessError/TimeoutExpired ->
    RuntimeError translation lives in one place instead of being
    reimplemented per caller. `error_label` overrides the tool name used in
    the message when `cmd[0]` alone isn't informative enough for the
    caller's context (e.g. "binwalk extracting <target>").
    """
    label = error_label or cmd[0]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                 check=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"{label} exited with status {exc.returncode}: "
            f"{(exc.stderr or '').strip()[:500]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{label} did not finish within {timeout}s "
                           f"(command: {' '.join(cmd)})") from exc
    return result.stdout
