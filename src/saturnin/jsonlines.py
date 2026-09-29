"""Validated JSON Lines parsing and interrupted-write recovery."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Callable, Collection, Iterator

PRIVATE_FILE_MODE = 0o600


class JSONLinesError(ValueError):
    def __init__(self, path: Path, line_number: int, cause: Exception) -> None:
        super().__init__(f"{path} at line {line_number}: {cause}")
        self.path = path
        self.line_number = line_number
        self.cause = cause


def atomic_replace_text(path: Path, text: str, *, mode: int | None = None) -> None:
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{os.urandom(6).hex()}.tmp"
    )
    target_mode = mode
    if target_mode is None:
        try:
            target_mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            target_mode = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            target_mode if target_mode is not None else 0o666,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            if target_mode is not None:
                os.fchmod(handle.fileno(), target_mode)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def durable_append_text(path: Path, text: str) -> None:
    existed = path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, PRIVATE_FILE_MODE)
    try:
        os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)
    if not existed:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def objects(
    text: str,
    path: Path,
    *,
    required_fields: Collection[str] = (),
    tolerate_unterminated_tail: bool = False,
    validator: Callable[[dict[str, Any]], None] | None = None,
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
            if validator is not None:
                validator(value)
            yield value
        except json.JSONDecodeError as exc:
            if tolerate_unterminated_tail and index == len(lines) - 1 and not terminated:
                return
            raise JSONLinesError(path, line_number, exc) from exc
        except (TypeError, ValueError) as exc:
            raise JSONLinesError(path, line_number, exc) from exc


def repair_unterminated_tail(
    text: str,
    path: Path,
    *,
    required_fields: Collection[str] = (),
    validator: Callable[[dict[str, Any]], None] | None = None,
) -> str:
    """Validate complete records and normalize or discard an interrupted tail."""
    if not text or text.endswith("\n"):
        list(objects(text, path, required_fields=required_fields, validator=validator))
        return text

    boundary = text.rfind("\n") + 1
    prefix, tail = text[:boundary], text[boundary:]
    list(objects(prefix, path, required_fields=required_fields, validator=validator))
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
    if validator is not None:
        try:
            validator(value)
        except (TypeError, ValueError) as exc:
            raise JSONLinesError(path, line_number, exc) from exc
    return text + "\n"
