# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Secret handling: values that must not be printed in the clear by accident.

Values are wrapped in :class:`Secret` at the point of discovery.  Exports and
reports run them through :class:`Masker`, which shows a shortened form unless the
operator switched *reveal* on for the current session.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import i18n


@dataclass(frozen=True)
class Secret:
    """A value that should be masked unless reveal mode is active."""

    value: str
    kind: str = "secret"
    keep_head: int = 0
    keep_tail: int = 4

    def __str__(self) -> str:
        return self.value if isinstance(self.value, str) else str(self.value)

    def masked(self) -> str:
        return mask_string(
            self.value, keep_head=self.keep_head, keep_tail=self.keep_tail
        )


def mask_string(value: str, keep_head: int = 0, keep_tail: int = 4) -> str:
    """``abcdefghij`` -> ``a…ij (10)`` style shortening with the original length."""
    if not value:
        return ""
    total = len(value)
    if keep_head + keep_tail >= total:
        return f"{value} ({total})"
    head = value[:keep_head] if keep_head else ""
    tail = value[-keep_tail:] if keep_tail else ""
    return f"{head}…{tail} ({total})"


def mask_token(value: str) -> str:
    """Tokens: keep a short prefix so the type stays recognisable."""
    return mask_string(value, keep_head=8, keep_tail=0)


def mask_phone(value: str) -> str:
    digits = [c for c in value if c.isdigit()]
    if len(digits) < 6:
        return mask_string(value, keep_head=2, keep_tail=2)
    tail = "".join(digits[-4:])
    prefix = value[: len(value) - len(tail)] if value.endswith(tail) else ""
    return f"{prefix}…{tail}"


class Masker:
    """Applies masking to :class:`Secret` values inside findings and exports."""

    def __init__(self, reveal: bool | None = None) -> None:
        self._reveal = reveal

    @property
    def reveal(self) -> bool:
        return i18n.reveal() if self._reveal is None else self._reveal

    def value(self, item: Any) -> Any:
        """Recursively render one value, masking secrets as needed."""
        if isinstance(item, Secret):
            return str(item) if self.reveal else item.masked()
        if isinstance(item, dict):
            return {key: self.value(val) for key, val in item.items()}
        if isinstance(item, (list, tuple)):
            return [self.value(val) for val in item]
        return item

    def redactable(self, item: Any) -> Any:
        """Same as :meth:`value` but keeps secrets as :class:`Secret` (for JSON)."""
        if isinstance(item, dict):
            return {key: self.redactable(val) for key, val in item.items()}
        if isinstance(item, (list, tuple)):
            return [self.redactable(val) for val in item]
        return item

    def as_json(self, item: Any) -> Any:
        """Plain JSON-safe structure; secrets become their masked or full text."""
        if isinstance(item, Secret):
            return str(item) if self.reveal else item.masked()
        if isinstance(item, dict):
            return {key: self.as_json(val) for key, val in item.items()}
        if isinstance(item, (list, tuple)):
            return [self.as_json(val) for val in item]
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        if isinstance(item, bytes):
            return item.hex()
        return str(item)


def note(value: str, kind: str) -> str:
    """Register a secret's fingerprint so the audit can look for its value later."""
    from . import secrets as _secrets

    return _secrets.REGISTRY.record(str(value), kind)


def secret_of(value: str, kind: str = "secret", keep_head: int = 0, keep_tail: int = 4) -> Secret:
    note(value, kind)
    return Secret(str(value), kind=kind, keep_head=keep_head, keep_tail=keep_tail)


def token_of(value: str) -> Secret:
    note(value, "token")
    return Secret(value, kind="token", keep_head=8, keep_tail=0)


def password_of(value: str) -> Secret:
    note(value, "password")
    return Secret(value, kind="password", keep_head=0, keep_tail=2)


def phone_of(value: str) -> Secret:
    note(value, "phone")
    return Secret(value, kind="phone", keep_head=0, keep_tail=4)
