"""FastAPI application: MIME email archive with stable fingerprints."""
from __future__ import annotations

import json
import sqlite3
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse

from . import __version__, db
from .errors import MimeError
from .fingerprint import message_fingerprint
from .mime_parser import parse_message

MAX_MESSAGE_BYTES = 25 * 1024 * 1024  # 25 MiB


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db()  # create schema on startup
    yield


app = FastAPI(
    title="MIME Archive Fingerprint API",
    version=__version__,
    description=(
        "Archives raw RFC 5322 messages, parses their MIME tree strictly and "
        "assigns stable content fingerprints that are insensitive to line "
        "endings, header case and header order."
    ),
    lifespan=lifespan,
)


@app.exception_handler(MimeError)
async def mime_error_handler(_request: Request, exc: MimeError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": exc.to_dict()})


def _error(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"detail": {"error": code, "message": message}}
    )


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/messages", status_code=201)
async def ingest_message(request: Request, response: Response) -> dict[str, Any]:
    """Ingest a raw RFC 5322 message (send it as the request body)."""
    raw = await request.body()
    if not raw:
        return _error(400, "empty_message", "request body is empty")  # type: ignore[return-value]
    if len(raw) > MAX_MESSAGE_BYTES:
        return _error(
            413,
            "message_too_large",
            f"message exceeds the {MAX_MESSAGE_BYTES}-byte limit",
        )  # type: ignore[return-value]
    # Parse fully and fingerprint before touching the database: a message
    # that fails parsing is rejected as a whole, nothing is written.
    root = parse_message(raw)
    fingerprint = message_fingerprint(root)
    try:
        result = db.store_message(raw, root, fingerprint)
    except sqlite3.Error as exc:
        return _error(500, "storage_error", str(exc))  # type: ignore[return-value]
    if not result["created"]:
        response.status_code = 200
    return {
        "id": result["id"],
        "fingerprint": fingerprint,
        "created": result["created"],
        "node_count": result["node_count"],
        "size_bytes": len(raw),
    }


@app.get("/api/v1/messages")
def list_messages(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    total, rows = db.list_messages(limit, offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [_message_summary(row) for row in rows],
    }


@app.get("/api/v1/messages/{fingerprint}")
def get_message(fingerprint: str) -> dict[str, Any]:
    row = db.get_message(fingerprint)
    if row is None:
        return _error(404, "not_found", f"no message with fingerprint {fingerprint!r}")  # type: ignore[return-value]
    result = _message_summary(row)
    nodes = db.get_message_nodes(row["id"])
    roots = [node for node in nodes if node["parent_id"] is None]
    if roots:
        result["headers"] = json.loads(roots[0]["headers_json"])
    return result


@app.get("/api/v1/messages/{fingerprint}/tree")
def get_message_tree(fingerprint: str) -> dict[str, Any]:
    row = db.get_message(fingerprint)
    if row is None:
        return _error(404, "not_found", f"no message with fingerprint {fingerprint!r}")  # type: ignore[return-value]
    nodes = db.get_message_nodes(row["id"])
    by_parent: dict[Any, list[Any]] = {}
    for node in nodes:
        by_parent.setdefault(node["parent_id"], []).append(node)

    def build(node_row: Any) -> dict[str, Any]:
        tree_node = _node_summary(node_row)
        tree_node["children"] = [
            build(child) for child in by_parent.get(node_row["id"], [])
        ]
        return tree_node

    roots = [build(node) for node in by_parent.get(None, [])]
    return {
        "fingerprint": fingerprint,
        "message_id": row["id"],
        "root": roots[0] if roots else None,
    }


@app.get("/api/v1/nodes/{node_id}")
def get_node(node_id: int) -> dict[str, Any]:
    row = db.get_node(node_id)
    if row is None:
        return _error(404, "not_found", f"no node with id {node_id}")  # type: ignore[return-value]
    result = _node_summary(row)
    result["message_id"] = row["message_id"]
    result["parent_id"] = row["parent_id"]
    result["leaf_text"] = row["leaf_text"]
    return result


# ---------------------------------------------------------------------------
# serialisation helpers
# ---------------------------------------------------------------------------


def _message_summary(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "subject": row["subject"],
        "from": row["from_addr"],
        "message_id": row["message_id"],
        "date": row["date"],
        "size_bytes": row["size_bytes"],
        "node_count": row["node_count"],
        "created_at": row["created_at"],
    }


def _node_summary(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "path": row["path"],
        "depth": row["depth"],
        "content_type": row["content_type"],
        "charset": row["charset"],
        "transfer_encoding": row["transfer_encoding"],
        "filename": row["filename"],
        "is_multipart": bool(row["is_multipart"]),
        "headers": json.loads(row["headers_json"]),
        "leaf_sha256": row["leaf_sha256"],
        "leaf_size": row["leaf_size"],
        "node_fingerprint": row["node_fingerprint"],
    }
