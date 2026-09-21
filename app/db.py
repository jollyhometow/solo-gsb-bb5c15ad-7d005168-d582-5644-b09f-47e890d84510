"""SQLite persistence layer for the MIME archive.

The database is created on startup (``init_db``).  Ingestion is atomic: a
message row and all of its MIME nodes are written in a single transaction,
so a failed ingest never leaves half-written data behind.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3

from .fingerprint import node_fingerprint
from .mime_parser import Node

DB_PATH = os.environ.get("ARCHIVE_DB_PATH", "archive.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY,
    fingerprint   TEXT NOT NULL UNIQUE,
    size_bytes    INTEGER NOT NULL,
    node_count    INTEGER NOT NULL,
    subject       TEXT,
    from_addr     TEXT,
    message_id    TEXT,
    date          TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS nodes (
    id                INTEGER PRIMARY KEY,
    message_id        INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    parent_id         INTEGER REFERENCES nodes(id),
    path              TEXT NOT NULL,
    depth             INTEGER NOT NULL,
    content_type      TEXT NOT NULL,
    charset           TEXT,
    transfer_encoding TEXT NOT NULL,
    filename          TEXT,
    is_multipart      INTEGER NOT NULL,
    headers_json      TEXT NOT NULL,
    leaf_text         TEXT,
    leaf_sha256       TEXT,
    leaf_size         INTEGER,
    node_fingerprint  TEXT NOT NULL,
    UNIQUE (message_id, path)
);

CREATE INDEX IF NOT EXISTS idx_nodes_message ON nodes(message_id);
CREATE INDEX IF NOT EXISTS idx_nodes_content_type ON nodes(content_type);
"""


def init_db() -> None:
    """Create the database schema if it does not exist yet."""
    directory = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _root_header(root: Node, name: str) -> str | None:
    for header_name, value in root.headers:
        if header_name.lower() == name:
            return value
    return None


def _count_nodes(node: Node) -> int:
    return 1 + sum(_count_nodes(child) for child in node.children or [])


def store_message(raw: bytes, root: Node, fingerprint: str) -> dict:
    """Persist *root* and its whole tree in one transaction.

    Returns ``{"id", "created", "node_count"}``.  If the fingerprint is
    already archived, nothing is written and ``created`` is ``False``.
    """
    conn = connect()
    try:
        with conn:  # commits on success, rolls back on any exception
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO messages
                    (fingerprint, size_bytes, node_count, subject, from_addr,
                     message_id, date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    len(raw),
                    _count_nodes(root),
                    _root_header(root, "subject"),
                    _root_header(root, "from"),
                    _root_header(root, "message-id"),
                    _root_header(root, "date"),
                ),
            )
            if cursor.rowcount == 0:
                row = conn.execute(
                    "SELECT id, node_count FROM messages WHERE fingerprint = ?",
                    (fingerprint,),
                ).fetchone()
                return {
                    "id": row["id"],
                    "created": False,
                    "node_count": row["node_count"],
                }
            message_id = cursor.lastrowid
            _insert_node(conn, message_id, root, parent_id=None, depth=0)
            return {
                "id": message_id,
                "created": True,
                "node_count": _count_nodes(root),
            }
    finally:
        conn.close()


def _insert_node(
    conn: sqlite3.Connection,
    message_id: int,
    node: Node,
    parent_id: int | None,
    depth: int,
) -> None:
    leaf_sha256 = (
        hashlib.sha256(node.leaf_bytes).hexdigest()
        if node.leaf_bytes is not None
        else None
    )
    cursor = conn.execute(
        """
        INSERT INTO nodes
            (message_id, parent_id, path, depth, content_type, charset,
             transfer_encoding, filename, is_multipart, headers_json,
             leaf_text, leaf_sha256, leaf_size, node_fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id,
            parent_id,
            node.path,
            depth,
            node.content_type,
            node.charset,
            node.transfer_encoding,
            node.filename,
            int(node.is_multipart),
            json.dumps(node.headers, ensure_ascii=False),
            node.leaf_text,
            leaf_sha256,
            len(node.leaf_bytes) if node.leaf_bytes is not None else None,
            "sha256:" + node_fingerprint(node),
        ),
    )
    node_id = cursor.lastrowid
    for child in node.children or []:
        _insert_node(conn, message_id, child, parent_id=node_id, depth=depth + 1)


def list_messages(limit: int, offset: int) -> tuple[int, list[sqlite3.Row]]:
    conn = connect()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM messages").fetchone()["n"]
        rows = conn.execute(
            "SELECT * FROM messages ORDER BY id LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return total, rows
    finally:
        conn.close()


def get_message(fingerprint: str) -> sqlite3.Row | None:
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM messages WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
    finally:
        conn.close()


def get_message_nodes(message_id: int) -> list[sqlite3.Row]:
    conn = connect()
    try:
        return conn.execute(
            "SELECT * FROM nodes WHERE message_id = ? ORDER BY id", (message_id,)
        ).fetchall()
    finally:
        conn.close()


def get_node(node_id: int) -> sqlite3.Row | None:
    conn = connect()
    try:
        return conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    finally:
        conn.close()
