"""Structured errors raised while processing MIME messages."""
from __future__ import annotations

from typing import Any


class MimeError(Exception):
    """A MIME processing failure located at a specific node of the MIME tree.

    ``path`` is the dotted, zero-based path of the offending node: the root
    message is ``"0"``, its first MIME part ``"0.0"``, the second part of a
    multipart nested inside that part ``"0.0.1"``, and so on.
    """

    def __init__(
        self,
        code: str,
        message: str,
        path: str = "0",
        content_type: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.content_type = content_type

    def to_dict(self) -> dict[str, Any]:
        detail: dict[str, Any] = {
            "error": self.code,
            "message": self.message,
            "path": self.path,
        }
        if self.content_type is not None:
            detail["content_type"] = self.content_type
        return detail
