from __future__ import annotations

import json
from json import JSONDecodeError
from typing import Any


class InputParseError(ValueError):
    """Raised when an analysis payload cannot be parsed as JSON or JSON Lines."""


def parse_analysis_input(raw: str) -> dict[str, Any]:
    if not raw.strip():
        return {}

    try:
        payload = json.loads(raw)
    except JSONDecodeError as json_error:
        return parse_jsonl_input(raw, json_error=json_error)

    if not isinstance(payload, dict):
        raise InputParseError("top-level JSON input must be an object")
    return payload


def parse_jsonl_input(raw: str, *, json_error: JSONDecodeError | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"messages": [], "events": [], "context": {"input_format": "jsonl"}}
    texts: list[str] = []
    records = 0

    for line_number, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        records += 1
        try:
            record = json.loads(stripped)
        except JSONDecodeError as exc:
            prefix = "invalid JSONL input"
            if json_error:
                prefix = f"invalid JSON input at line {json_error.lineno}, then invalid JSONL input"
            raise InputParseError(f"{prefix} at line {line_number}: {exc.msg}") from exc
        merge_jsonl_record(payload, record, line_number=line_number, texts=texts)

    if records == 0:
        return {}
    if texts:
        payload["text"] = "\n".join(texts)
    payload["context"]["jsonl_records"] = records
    return payload


def merge_jsonl_record(payload: dict[str, Any], record: Any, *, line_number: int, texts: list[str]) -> None:
    if not isinstance(record, dict):
        raise InputParseError(f"invalid JSONL input at line {line_number}: each line must be an object")

    if is_payload_fragment(record):
        merge_payload_record(payload, record, line_number=line_number, texts=texts)
        return

    record_type = str(record.get("type") or record.get("kind") or "").lower()
    if record_type == "message" or "role" in record:
        payload["messages"].append(message_from_record(record, line_number=line_number))
        return

    if is_event_record(record):
        payload["events"].append(event_from_record(record, line_number=line_number))
        return

    if "text" in record:
        texts.append(str(record["text"]))
        return

    payload["events"].append(event_from_record(record, line_number=line_number, kind="event"))


def merge_payload_record(payload: dict[str, Any], record: dict[str, Any], *, line_number: int, texts: list[str]) -> None:
    for message in list_items(record, "messages", line_number=line_number):
        if not isinstance(message, dict):
            raise InputParseError(f"invalid JSONL input at line {line_number}: messages entries must be objects")
        payload["messages"].append(message_from_record(message, line_number=line_number))

    for event in list_items(record, "events", line_number=line_number):
        if not isinstance(event, dict):
            raise InputParseError(f"invalid JSONL input at line {line_number}: events entries must be objects")
        payload["events"].append(event_from_record(event, line_number=line_number))

    if "text" in record:
        texts.append(str(record["text"]))

    context = record.get("context")
    if context is not None:
        if not isinstance(context, dict):
            raise InputParseError(f"invalid JSONL input at line {line_number}: context must be an object")
        payload["context"].update(context)


def list_items(record: dict[str, Any], key: str, *, line_number: int) -> list[Any]:
    if key not in record:
        return []
    value = record[key]
    if not isinstance(value, list):
        raise InputParseError(f"invalid JSONL input at line {line_number}: {key} must be a list")
    return value


def message_from_record(record: dict[str, Any], *, line_number: int) -> dict[str, Any]:
    return {
        "role": record.get("role", "unknown"),
        "content": record.get("content", record.get("text", "")),
        "name": record.get("name"),
        "metadata": metadata_for(record, line_number=line_number),
    }


def event_from_record(record: dict[str, Any], *, line_number: int, kind: str | None = None) -> dict[str, Any]:
    content = record.get("content", record.get("text", record.get("output", "")))
    command = record.get("command", record.get("cmd"))
    file_path = record.get("file_path", record.get("path"))
    tool_name = record.get("tool_name", record.get("tool"))
    return {
        "kind": kind or record.get("kind") or record.get("type") or "event",
        "content": content,
        "tool_name": tool_name,
        "command": command,
        "file_path": file_path,
        "metadata": metadata_for(record, line_number=line_number),
    }


def metadata_for(record: dict[str, Any], *, line_number: int) -> dict[str, Any]:
    raw_metadata = record.get("metadata") or {}
    if not isinstance(raw_metadata, dict):
        raise InputParseError(f"invalid JSONL input at line {line_number}: metadata must be an object")
    metadata = dict(raw_metadata)
    metadata.setdefault("jsonl_line", line_number)
    return metadata


def is_event_record(record: dict[str, Any]) -> bool:
    return any(key in record for key in ("kind", "command", "cmd", "file_path", "path", "tool_name", "tool", "output"))


def is_payload_fragment(record: dict[str, Any]) -> bool:
    return "messages" in record or "events" in record or (
        "context" in record and "role" not in record and not is_event_record(record)
    )
