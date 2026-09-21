"""End-to-end tests for the MIME archive fingerprint API."""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A TestClient backed by a fresh, temporary SQLite database."""
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    with TestClient(app) as test_client:
        yield test_client


def ingest(client: TestClient, raw: bytes | str):
    if isinstance(raw, str):
        raw = raw.encode()
    return client.post(
        "/api/v1/messages", content=raw, headers={"Content-Type": "message/rfc822"}
    )


SIMPLE = (
    "From: Alice <alice@example.com>\n"
    "To: Bob <bob@example.com>\n"
    "Subject: Hello there\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "Hello, world!\n"
)

MULTIPART = (
    "From: Alice <alice@example.com>\n"
    "Subject: With attachment\n"
    "Content-Type: multipart/mixed; boundary=frontier\n"
    "\n"
    "preamble\n"
    "--frontier\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "See attached.\n"
    "--frontier\n"
    "Content-Type: application/octet-stream; name=data.bin\n"
    "Content-Transfer-Encoding: base64\n"
    "Content-Disposition: attachment; filename=data.bin\n"
    "\n"
    "AAECAwQF\n"
    "--frontier--\n"
    "epilogue\n"
)

NESTED = (
    "Content-Type: multipart/mixed; boundary=outer\n"
    "\n"
    "--outer\n"
    "Content-Type: text/plain\n"
    "\n"
    "first\n"
    "--outer\n"
    "Content-Type: multipart/alternative; boundary=inner\n"
    "\n"
    "--inner\n"
    "Content-Type: text/plain; charset=utf-8\n"
    "\n"
    "plain version\n"
    "--inner\n"
    "Content-Type: text/html; charset=utf-8\n"
    "\n"
    "<p>html version</p>\n"
    "--inner--\n"
    "--outer--\n"
)


# ---------------------------------------------------------------------------
# health & basic ingest
# ---------------------------------------------------------------------------


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_simple_message(client):
    response = ingest(client, SIMPLE)
    assert response.status_code == 201
    body = response.json()
    assert body["created"] is True
    assert body["fingerprint"].startswith("sha256:")
    assert len(body["fingerprint"]) == len("sha256:") + 64
    assert body["node_count"] == 1


def test_ingest_empty_body_rejected(client):
    response = client.post("/api/v1/messages", content=b"")
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "empty_message"


# ---------------------------------------------------------------------------
# fingerprint stability
# ---------------------------------------------------------------------------


def test_line_endings_do_not_change_fingerprint(client):
    lf = ingest(client, SIMPLE).json()["fingerprint"]
    crlf = ingest(client, SIMPLE.replace("\n", "\r\n")).json()["fingerprint"]
    assert lf == crlf


def test_header_case_does_not_change_fingerprint(client):
    lower = ingest(client, SIMPLE).json()["fingerprint"]
    shouted = SIMPLE.replace("Content-Type: text/plain", "CONTENT-TYPE: TEXT/PLAIN")
    shouted = shouted.replace("Subject: Hello", "SUBJECT: Hello")
    upper = ingest(client, shouted).json()["fingerprint"]
    assert lower == upper


def test_header_order_does_not_change_fingerprint(client):
    original = ingest(client, SIMPLE).json()["fingerprint"]
    reordered = (
        "Subject: Hello there\n"
        "To: Bob <bob@example.com>\n"
        "From: Alice <alice@example.com>\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        "Hello, world!\n"
    )
    assert ingest(client, reordered).json()["fingerprint"] == original


def test_charset_case_and_quoting_do_not_change_fingerprint(client):
    plain = ingest(client, SIMPLE).json()["fingerprint"]
    variant = SIMPLE.replace(
        "Content-Type: text/plain; charset=utf-8",
        'Content-Type: text/plain; Charset="UTF-8"',
    )
    assert ingest(client, variant).json()["fingerprint"] == plain


def test_boundary_value_does_not_change_fingerprint(client):
    first = ingest(client, MULTIPART).json()["fingerprint"]
    renamed = MULTIPART.replace("frontier", "other-boundary")
    assert ingest(client, renamed).json()["fingerprint"] == first


def test_different_content_changes_fingerprint(client):
    first = ingest(client, SIMPLE).json()["fingerprint"]
    changed = ingest(client, SIMPLE.replace("Hello, world!", "Goodbye.")).json()
    assert changed["fingerprint"] != first


def test_reingest_is_idempotent(client):
    first = ingest(client, SIMPLE)
    assert first.status_code == 201
    second = ingest(client, SIMPLE)
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["id"] == first.json()["id"]
    assert client.get("/api/v1/messages").json()["total"] == 1


# ---------------------------------------------------------------------------
# transfer encodings & charsets
# ---------------------------------------------------------------------------


def test_base64_body_decoded_for_fingerprint(client):
    plain = ingest(client, SIMPLE).json()["fingerprint"]
    encoded = (
        "From: Alice <alice@example.com>\n"
        "To: Bob <bob@example.com>\n"
        "Subject: Hello there\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "SGVsbG8sIHdvcmxkIQo=\n"
    )
    assert ingest(client, encoded).json()["fingerprint"] == plain


def test_quoted_printable_body_decoded(client):
    message = (
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: quoted-printable\n"
        "\n"
        "caf=C3=A9 au lait\n"
    )
    response = ingest(client, message)
    assert response.status_code == 201
    listing = client.get("/api/v1/messages").json()
    tree = client.get(
        f"/api/v1/messages/{listing['items'][0]['fingerprint']}/tree"
    ).json()
    assert tree["root"]["leaf_sha256"] == hashlib.sha256(
        "café au lait\n".encode()
    ).hexdigest()


def test_invalid_base64_rejected_with_path(client):
    message = (
        "Content-Type: multipart/mixed; boundary=b\n"
        "\n"
        "--b\n"
        "Content-Type: text/plain\n"
        "\n"
        "ok\n"
        "--b\n"
        "Content-Type: application/octet-stream\n"
        "Content-Transfer-Encoding: base64\n"
        "\n"
        "not!!base64!!\n"
        "--b--\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_base64"
    assert detail["path"] == "0.1"


def test_invalid_quoted_printable_rejected(client):
    message = (
        "Content-Type: text/plain\n"
        "Content-Transfer-Encoding: quoted-printable\n"
        "\n"
        "price=100=USD\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "invalid_quoted_printable"


def test_unknown_transfer_encoding_rejected(client):
    message = "Content-Transfer-Encoding: x-uuencode\n\nbegin 644 x\n"
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "unknown_transfer_encoding"


def test_unknown_charset_rejected(client):
    message = "Content-Type: text/plain; charset=klingon\n\nhello\n"
    response = ingest(client, message)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "unknown_charset"
    assert detail["path"] == "0"


def test_undecodable_charset_rejected(client):
    message = b"Content-Type: text/plain; charset=utf-8\n\ninvalid: \xff\xfe\n"
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "decode_failed"


def test_latin1_leaf_decoded_to_text(client):
    message = "Content-Type: text/plain; charset=iso-8859-1\n\ncaf\xe9\n".encode(
        "latin-1"
    )
    response = ingest(client, message)
    assert response.status_code == 201
    listing = client.get("/api/v1/messages").json()
    fingerprint = listing["items"][0]["fingerprint"]
    tree = client.get(f"/api/v1/messages/{fingerprint}/tree").json()
    node = client.get(f"/api/v1/nodes/{tree['root']['id']}").json()
    assert node["leaf_text"] == "café\n"


# ---------------------------------------------------------------------------
# multipart structure errors
# ---------------------------------------------------------------------------


def test_missing_boundary_parameter_rejected(client):
    message = "Content-Type: multipart/mixed\n\n--b\n\nx\n--b--\n"
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "missing_boundary"


def test_boundary_not_found_rejected(client):
    message = (
        "Content-Type: multipart/mixed; boundary=ghost\n"
        "\n"
        "no delimiters here at all\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "boundary_not_found"
    assert detail["path"] == "0"
    assert detail["content_type"] == "multipart/mixed"


def test_unterminated_multipart_rejected(client):
    message = (
        "Content-Type: multipart/mixed; boundary=b\n"
        "\n"
        "--b\n"
        "Content-Type: text/plain\n"
        "\n"
        "never closed\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "unterminated_multipart"


def test_nested_error_reports_nested_path(client):
    message = (
        "Content-Type: multipart/mixed; boundary=outer\n"
        "\n"
        "--outer\n"
        "Content-Type: text/plain\n"
        "\n"
        "fine\n"
        "--outer\n"
        "Content-Type: multipart/alternative; boundary=missing\n"
        "\n"
        "no inner delimiters\n"
        "--outer--\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "boundary_not_found"
    assert detail["path"] == "0.1"


def test_duplicate_parameter_rejected(client):
    message = (
        "Content-Type: text/plain; charset=utf-8; CHARSET=iso-8859-1\n"
        "\n"
        "duplicate charset parameter\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "duplicate_parameter"
    assert detail["path"] == "0"


def test_duplicate_boundary_parameter_rejected(client):
    message = (
        "Content-Type: multipart/mixed; boundary=a; boundary=b\n"
        "\n"
        "--a\n\nx\n--a--\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "duplicate_parameter"


def test_duplicate_singleton_header_rejected(client):
    message = (
        "Content-Type: text/plain\n"
        "Content-Type: text/html\n"
        "\n"
        "two content types\n"
    )
    response = ingest(client, message)
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "duplicate_header"


def test_malformed_header_rejected(client):
    response = ingest(client, "Subject ok\nno colon here\n\nbody\n")
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "malformed_header"


# ---------------------------------------------------------------------------
# atomicity: failures must not leave partial data
# ---------------------------------------------------------------------------


def test_failed_ingest_writes_nothing(client):
    bad = (
        "Content-Type: multipart/mixed; boundary=ghost\n"
        "\n"
        "no boundary in body\n"
    )
    assert ingest(client, bad).status_code == 422
    assert client.get("/api/v1/messages").json()["total"] == 0


def test_failed_ingest_after_success_keeps_previous(client):
    assert ingest(client, SIMPLE).status_code == 201
    assert ingest(client, "Content-Type: text/plain; charset=nope\n\nx\n").status_code == 422
    listing = client.get("/api/v1/messages").json()
    assert listing["total"] == 1


# ---------------------------------------------------------------------------
# tree & queries
# ---------------------------------------------------------------------------


def test_multipart_tree_structure(client):
    response = ingest(client, MULTIPART)
    fingerprint = response.json()["fingerprint"]
    assert response.json()["node_count"] == 3

    tree = client.get(f"/api/v1/messages/{fingerprint}/tree").json()
    root = tree["root"]
    assert root["path"] == "0"
    assert root["content_type"] == "multipart/mixed"
    assert root["is_multipart"] is True
    assert len(root["children"]) == 2

    text_part, attachment = root["children"]
    assert text_part["path"] == "0.0"
    assert text_part["content_type"] == "text/plain"
    assert text_part["charset"] == "utf-8"
    assert attachment["path"] == "0.1"
    assert attachment["content_type"] == "application/octet-stream"
    assert attachment["filename"] == "data.bin"
    assert attachment["leaf_sha256"] == hashlib.sha256(b"\x00\x01\x02\x03\x04\x05").hexdigest()
    assert attachment["leaf_size"] == 6


def test_nested_tree_paths(client):
    fingerprint = ingest(client, NESTED).json()["fingerprint"]
    tree = client.get(f"/api/v1/messages/{fingerprint}/tree").json()
    root = tree["root"]
    assert [child["path"] for child in root["children"]] == ["0.0", "0.1"]
    nested = root["children"][1]
    assert nested["content_type"] == "multipart/alternative"
    assert [child["path"] for child in nested["children"]] == ["0.1.0", "0.1.1"]


def test_node_detail_contains_decoded_text(client):
    fingerprint = ingest(client, MULTIPART).json()["fingerprint"]
    tree = client.get(f"/api/v1/messages/{fingerprint}/tree").json()
    text_part = tree["root"]["children"][0]
    node = client.get(f"/api/v1/nodes/{text_part['id']}").json()
    # The CRLF immediately before a boundary delimiter belongs to the
    # delimiter (RFC 2046), so the part body has no trailing newline.
    assert node["leaf_text"] == "See attached."
    assert node["message_id"] is not None
    assert node["parent_id"] == tree["root"]["id"]


def test_message_detail_and_listing(client):
    fingerprint = ingest(client, SIMPLE).json()["fingerprint"]
    detail = client.get(f"/api/v1/messages/{fingerprint}").json()
    assert detail["subject"] == "Hello there"
    assert detail["from"] == "Alice <alice@example.com>"
    assert ["Subject", "Hello there"] in detail["headers"]

    listing = client.get("/api/v1/messages").json()
    assert listing["total"] == 1
    assert listing["items"][0]["fingerprint"] == fingerprint


def test_missing_message_and_node_return_404(client):
    response = client.get("/api/v1/messages/sha256:" + "0" * 64)
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "not_found"
    assert client.get("/api/v1/nodes/999").status_code == 404


def test_pagination(client):
    for index in range(5):
        ingest(client, f"Subject: n{index}\n\nbody {index}\n")
    page = client.get("/api/v1/messages?limit=2&offset=2").json()
    assert page["total"] == 5
    assert len(page["items"]) == 2
