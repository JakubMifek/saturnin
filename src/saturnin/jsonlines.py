"""Validated JSON Lines parsing and interrupted-write recovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Collection, Iterator


class JSONLinesError(ValueError):
    def __init__(self, path: Path, line_number: int, cause: Exception) -> None:
        super().__init__(f"{path} at line {line_number}: {cause}")
        self.path = path
        self.line_number = line_number
        self.cause = cause


def objects(
    text: str,
    path: Path,
    *,
    required_fields: Collection[str] = (),
    tolerate_unterminated_tail: bool = False,
) -> Iterator[dict[str, Any]]:
    lines = [
        (line_number, line, line.endswith("\n"))
        for line_number, line in enumerate(text.splitlines(keepends=True), start=1)
        if line.strip()
    ]
    for index, (line_number, line, terminated) in enumerate(lines):
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError("record must be a JSON object")
            missing = sorted(set(required_fields) - set(value))
            if missing:
                raise TypeError(f"record is missing required field(s): {', '.join(missing)}")
            yield value
        except json.JSONDecodeError as exc:
            if tolerate_unterminated_tail and index == len(lines) - 1 and not terminated:
                return
            raise JSONLinesError(path, line_number, exc) from exc
        except TypeError as exc:
            raise JSONLinesError(path, line_number, exc) from exc


def repair_unterminated_tail(
    text: str, path: Path, *, required_fields: Collection[str] = ()
) -> str:
    """Validate complete records and normalize or discard an interrupted tail."""
    if not text or text.endswith("\n"):
        list(objects(text, path, required_fields=required_fields))
        return text

    boundary = text.rfind("\n") + 1
    prefix, tail = text[:boundary], text[boundary:]
    list(objects(prefix, path, required_fields=required_fields))
    if not tail.strip():
        return prefix
    line_number = prefix.count("\n") + 1
    try:
        value = json.loads(tail)
    except json.JSONDecodeError:
        return prefix
    if not isinstance(value, dict):
        raise JSONLinesError(path, line_number, TypeError("record must be a JSON object"))
    missing = sorted(set(required_fields) - set(value))
    if missing:
        raise JSONLinesError(
            path,
            line_number,
            TypeError(f"record is missing required field(s): {', '.join(missing)}"),
        )
    return text + "\n"
