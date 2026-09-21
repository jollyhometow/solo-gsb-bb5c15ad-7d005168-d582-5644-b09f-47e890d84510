"""Strict recursive MIME parser.

Parses raw RFC 5322 messages into a :class:`Node` tree.  The parser is
deliberately strict: structural problems (broken multipart boundaries,
duplicated header parameters, undecodable transfer encodings or charsets,
...) raise :class:`~app.errors.MimeError` carrying the dotted path of the
offending node instead of being silently repaired.

Line endings are normalised to ``\\n`` up front, so messages that differ
only in CRLF vs LF serialisation parse to identical trees.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import quopri
import re
from dataclasses import dataclass, field

from .errors import MimeError

MAX_DEPTH = 50
MAX_NODES = 10_000

# RFC 5322 field name: printable ASCII except ':'.
_HEADER_NAME_RE = re.compile(r"^[!-9;-~]+$")
# token (RFC 2045) optionally with a single "/" for media types.
_STRUCTURED_MAIN_RE = re.compile(r"^[a-z0-9!#$&^_.+\-]+(/[a-z0-9!#$&^_.+\-]+)?$")
_TOKEN_RE = re.compile(r"^[a-z0-9!#$&^_.+\-]+$")
# A '=' in quoted-printable must be followed by two hex digits or a soft
# line break ('=\n' after newline normalisation).
_QP_INVALID_RE = re.compile(rb"=(?![0-9A-Fa-f]{2}|\n)")
_WS_RUN_RE = re.compile(rb"\s+")

TRANSFER_ENCODINGS = {"7bit", "8bit", "binary", "base64", "quoted-printable"}
# Headers that must appear at most once per MIME entity.
SINGLETON_HEADERS = {
    "content-type",
    "content-transfer-encoding",
    "content-disposition",
    "mime-version",
}
DEFAULT_CONTENT_TYPE = "text/plain"
DEFAULT_CHARSET = "us-ascii"


@dataclass
class Node:
    """One entity of a MIME tree (the root message or a single part)."""

    path: str
    headers: list[tuple[str, str]]  # (name, unfolded value), original order/case
    content_type: str  # normalised "maintype/subtype", lower case
    params: list[tuple[str, str]]  # Content-Type parameters
    transfer_encoding: str
    disposition: str | None = None
    disposition_params: list[tuple[str, str]] = field(default_factory=list)
    charset: str | None = None
    filename: str | None = None
    children: list["Node"] | None = None  # None => leaf node
    leaf_bytes: bytes | None = None  # transfer-decoded body (leaf only)
    leaf_text: str | None = None  # charset-decoded body (textual leaf only)

    @property
    def is_multipart(self) -> bool:
        return self.children is not None


class _Context:
    """Mutable bookkeeping shared across the recursive parse."""

    def __init__(self) -> None:
        self.nodes = 0


def parse_message(raw: bytes) -> Node:
    """Parse *raw* RFC 5322 bytes and return the root :class:`Node`.

    Raises :class:`MimeError` on any structural or decoding problem.
    """
    data = raw.replace(b"\r\n", b"\n")
    return _parse_node(data, path="0", depth=0, ctx=_Context())


def _parse_node(data: bytes, path: str, depth: int, ctx: _Context) -> Node:
    if depth > MAX_DEPTH:
        raise MimeError(
            "nesting_too_deep", f"MIME nesting exceeds {MAX_DEPTH} levels", path
        )
    ctx.nodes += 1
    if ctx.nodes > MAX_NODES:
        raise MimeError(
            "too_many_nodes", f"message has more than {MAX_NODES} MIME nodes", path
        )

    head, body = _split_head_body(data)
    headers = _parse_headers(head, path)
    _check_singletons(headers, path)

    ctype_value = _header_value(headers, "content-type")
    if ctype_value is None:
        content_type, params = DEFAULT_CONTENT_TYPE, []
    else:
        content_type, params = parse_structured_header(
            ctype_value, path, what="content-type"
        )
        if "/" not in content_type:
            raise MimeError(
                "invalid_content_type",
                f"malformed Content-Type {content_type!r} (expected type/subtype)",
                path,
            )

    cte_value = _header_value(headers, "content-transfer-encoding")
    transfer_encoding = (
        re.sub(r"\s+", "", cte_value).lower() if cte_value is not None else "7bit"
    )
    if transfer_encoding not in TRANSFER_ENCODINGS:
        raise MimeError(
            "unknown_transfer_encoding",
            f"unsupported Content-Transfer-Encoding {transfer_encoding!r}",
            path,
            content_type,
        )

    disposition: str | None = None
    disposition_params: list[tuple[str, str]] = []
    disp_value = _header_value(headers, "content-disposition")
    if disp_value is not None:
        disposition, disposition_params = parse_structured_header(
            disp_value, path, what="content-disposition"
        )

    node = Node(
        path=path,
        headers=headers,
        content_type=content_type,
        params=params,
        transfer_encoding=transfer_encoding,
        disposition=disposition,
        disposition_params=disposition_params,
    )
    node.charset = _param(params, "charset")
    node.filename = _param(disposition_params, "filename") or _param(params, "name")

    maintype = content_type.split("/", 1)[0]
    if maintype == "multipart":
        if transfer_encoding not in ("7bit", "8bit", "binary"):
            raise MimeError(
                "invalid_transfer_encoding",
                f"multipart entities must not use {transfer_encoding!r} encoding",
                path,
                content_type,
            )
        boundary = _param(params, "boundary")
        if not boundary:
            raise MimeError(
                "missing_boundary",
                "multipart Content-Type lacks a boundary parameter",
                path,
                content_type,
            )
        _validate_boundary(boundary, path, content_type)
        chunks = _split_multipart(body, boundary, path, content_type)
        node.children = [
            _parse_node(chunk, f"{path}.{index}", depth + 1, ctx)
            for index, chunk in enumerate(chunks)
        ]
    else:
        node.leaf_bytes = _transfer_decode(body, transfer_encoding, path, content_type)
        if maintype == "text":
            charset = node.charset or DEFAULT_CHARSET
            node.charset = charset
            node.leaf_text = _charset_decode(node.leaf_bytes, charset, path, content_type)
    return node


def _split_head_body(data: bytes) -> tuple[bytes, bytes]:
    index = data.find(b"\n\n")
    if index == -1:
        return data, b""
    return data[:index], data[index + 2 :]


def _parse_headers(head: bytes, path: str) -> list[tuple[str, str]]:
    headers: list[tuple[str, str]] = []
    if not head:
        return headers
    for raw_line in head.split(b"\n"):
        if raw_line[:1] in (b" ", b"\t"):
            if not headers:
                raise MimeError(
                    "malformed_header",
                    "header continuation line without a preceding header",
                    path,
                )
            name, value = headers[-1]
            headers[-1] = (name, value + " " + raw_line.strip().decode("latin-1"))
            continue
        name_b, sep, value_b = raw_line.partition(b":")
        if not sep:
            raise MimeError(
                "malformed_header",
                f"header line lacks a colon: {raw_line[:60]!r}",
                path,
            )
        name = name_b.decode("latin-1")
        if not _HEADER_NAME_RE.match(name):
            raise MimeError(
                "malformed_header", f"invalid header name {name!r}", path
            )
        headers.append((name, value_b.decode("latin-1").strip()))
    return headers


def _check_singletons(headers: list[tuple[str, str]], path: str) -> None:
    seen: set[str] = set()
    for name, _value in headers:
        lowered = name.lower()
        if lowered in SINGLETON_HEADERS:
            if lowered in seen:
                raise MimeError(
                    "duplicate_header",
                    f"header {lowered!r} appears more than once",
                    path,
                )
            seen.add(lowered)


def parse_structured_header(
    value: str, path: str, what: str
) -> tuple[str, list[tuple[str, str]]]:
    """Parse a ``main; name=value; ...`` header (quote-aware).

    Returns the lower-cased main value and the parameter list with
    lower-cased names.  Raises :class:`MimeError` on malformed or repeated
    parameters.
    """
    segments = _split_quoted(value, ";")
    main = segments[0].strip().lower()
    if not _STRUCTURED_MAIN_RE.match(main):
        raise MimeError(
            f"invalid_{what.replace('-', '_')}",
            f"malformed {what} value {value.strip()!r}",
            path,
        )
    params: list[tuple[str, str]] = []
    seen: set[str] = set()
    for segment in segments[1:]:
        if not segment.strip():
            continue  # tolerate a trailing ';'
        name, sep, raw_val = segment.partition("=")
        if not sep:
            raise MimeError(
                "malformed_parameter",
                f"{what} parameter {segment.strip()!r} lacks '='",
                path,
            )
        name = name.strip().lower()
        if not _TOKEN_RE.match(name):
            raise MimeError(
                "malformed_parameter",
                f"invalid {what} parameter name {name!r}",
                path,
            )
        if name in seen:
            raise MimeError(
                "duplicate_parameter",
                f"{what} parameter {name!r} is repeated",
                path,
            )
        seen.add(name)
        params.append((name, _unquote(raw_val.strip(), path, what)))
    return main, params


def _split_quoted(value: str, sep: str) -> list[str]:
    """Split *value* on *sep*, ignoring separators inside quoted strings."""
    parts: list[str] = []
    buf: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\" and quoted:
            buf.append(char)
            escaped = True
        elif char == '"':
            buf.append(char)
            quoted = not quoted
        elif char == sep and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(char)
    parts.append("".join(buf))
    return parts


def _unquote(value: str, path: str, what: str) -> str:
    if not value.startswith('"'):
        return value
    if len(value) < 2 or not value.endswith('"'):
        raise MimeError(
            "malformed_parameter",
            f"unterminated quoted string in {what}: {value!r}",
            path,
        )
    inner = value[1:-1]
    out: list[str] = []
    index = 0
    while index < len(inner):
        if inner[index] == "\\" and index + 1 < len(inner):
            out.append(inner[index + 1])
            index += 2
        else:
            out.append(inner[index])
            index += 1
    return "".join(out)


def _validate_boundary(boundary: str, path: str, content_type: str) -> None:
    if len(boundary) > 70:
        raise MimeError(
            "invalid_boundary",
            "boundary is longer than 70 characters",
            path,
            content_type,
        )
    if (
        not boundary
        or boundary != boundary.strip()
        or not all(32 < ord(char) < 127 or char == " " for char in boundary)
    ):
        raise MimeError(
            "invalid_boundary",
            f"boundary {boundary!r} contains invalid characters",
            path,
            content_type,
        )


def _split_multipart(
    body: bytes, boundary: str, path: str, content_type: str
) -> list[bytes]:
    delimiter = b"--" + boundary.encode("ascii")
    closing = delimiter + b"--"
    parts: list[bytes] = []
    current: list[bytes] | None = None
    saw_delimiter = False
    saw_closing = False
    for line in body.split(b"\n"):
        # Transport padding (trailing WSP) is allowed on delimiter lines.
        stripped = line.rstrip(b" \t")
        if stripped == delimiter:
            saw_delimiter = True
            if current is not None:
                parts.append(b"\n".join(current))
            current = []
        elif stripped == closing:
            if current is not None:
                parts.append(b"\n".join(current))
            current = None
            saw_closing = True
            break  # everything after the closing delimiter is the epilogue
        elif current is not None:
            current.append(line)
        # lines before the first delimiter are the preamble: ignored
    if not saw_delimiter:
        raise MimeError(
            "boundary_not_found",
            f"boundary {boundary!r} never appears in the body",
            path,
            content_type,
        )
    if not saw_closing:
        raise MimeError(
            "unterminated_multipart",
            f"closing delimiter '--{boundary}--' is missing",
            path,
            content_type,
        )
    return parts


def _transfer_decode(
    body: bytes, encoding: str, path: str, content_type: str
) -> bytes:
    if encoding in ("7bit", "8bit", "binary"):
        return body
    if encoding == "base64":
        compact = _WS_RUN_RE.sub(b"", body)
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise MimeError(
                "invalid_base64", f"invalid base64 body: {exc}", path, content_type
            ) from exc
    if encoding == "quoted-printable":
        bad = _QP_INVALID_RE.search(body)
        if bad is not None:
            raise MimeError(
                "invalid_quoted_printable",
                f"invalid '=' escape at body offset {bad.start()}",
                path,
                content_type,
            )
        return quopri.decodestring(body)
    raise AssertionError(f"unhandled transfer encoding {encoding!r}")


def _charset_decode(
    data: bytes, charset: str, path: str, content_type: str
) -> str:
    try:
        info = codecs.lookup(charset)
    except LookupError:
        raise MimeError(
            "unknown_charset", f"unknown charset {charset!r}", path, content_type
        ) from None
    try:
        return data.decode(info.name, errors="strict")
    except UnicodeDecodeError as exc:
        raise MimeError(
            "decode_failed",
            f"body cannot be decoded as {charset}: {exc}",
            path,
            content_type,
        ) from exc


def _header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    for header_name, value in headers:
        if header_name.lower() == name:
            return value
    return None


def _param(params: list[tuple[str, str]], name: str) -> str | None:
    for param_name, value in params:
        if param_name == name:
            return value
    return None
