"""Stable content fingerprints for parsed MIME trees.

The fingerprint of a message is the SHA-256 of a canonical serialisation of
its MIME tree:

* header field names are lower-cased, values are unfolded and whitespace is
  collapsed, so header case and folding do not affect the fingerprint;
* headers are sorted, so header order does not affect the fingerprint;
* ``Content-Type`` / ``Content-Disposition`` values are canonicalised
  (lower-cased main value and parameter names, parameters sorted, charset
  value lower-cased) and the multipart ``boundary`` parameter value is
  blanked out — it is a serialisation artefact, not content;
* the ``Content-Transfer-Encoding`` header is excluded entirely: leaf
  content is hashed in decoded form, so the encoding that happened to be
  used on the wire is a serialisation artefact as well;
* multipart nodes hash the ordered fingerprints of their children
  (preamble/epilogue are ignored);
* leaf nodes hash their *decoded* content: transfer-decoded, and for
  ``text/*`` additionally charset-decoded to Unicode.  Line endings were
  already normalised to ``\\n`` during parsing, so CRLF and LF
  serialisations of the same message share one fingerprint.
"""
from __future__ import annotations

import hashlib

from .mime_parser import Node, parse_structured_header

_FORMAT_TAG = b"mime-archive/v1\n"


def _collapse_ws(value: str) -> str:
    return " ".join(value.split())


def _canonical_header_value(name: str, value: str) -> str:
    value = _collapse_ws(value)
    if name in ("content-type", "content-disposition"):
        # Already validated during parsing, so this cannot raise.
        main, params = parse_structured_header(value, path="-", what=name)
        canonical_params = []
        for param_name, param_value in sorted(params):
            if param_name == "boundary":
                param_value = ""  # serialisation artefact, not content
            elif param_name == "charset":
                param_value = param_value.lower()
            canonical_params.append(f"{param_name}={param_value}")
        return main + "".join(f"; {param}" for param in canonical_params)
    return value


# Headers excluded from the fingerprint: their values describe how the
# content was serialised on the wire, not the content itself (leaf content
# is hashed after transfer-decoding).
_EXCLUDED_HEADERS = {"content-transfer-encoding"}


def node_fingerprint(node: Node) -> str:
    """Return the hex SHA-256 fingerprint of *node* and its subtree."""
    digest = hashlib.sha256()
    digest.update(_FORMAT_TAG)
    pairs = sorted(
        (name.lower(), _canonical_header_value(name.lower(), value))
        for name, value in node.headers
        if name.lower() not in _EXCLUDED_HEADERS
    )
    for name, value in pairs:
        digest.update(b"H\x00")
        digest.update(name.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    if node.is_multipart:
        digest.update(b"M\x00")
        for child in node.children or []:
            digest.update(bytes.fromhex(node_fingerprint(child)))
    else:
        digest.update(b"L\x00")
        if node.leaf_text is not None:
            digest.update(b"T\x00")
            digest.update(node.leaf_text.encode("utf-8"))
        else:
            digest.update(b"B\x00")
            digest.update(node.leaf_bytes or b"")
    return digest.hexdigest()


def message_fingerprint(root: Node) -> str:
    """Return the prefixed fingerprint identifying a whole message."""
    return "sha256:" + node_fingerprint(root)
