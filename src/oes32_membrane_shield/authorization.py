"""External authorization primitives for the OES-32 shield.

Private signing keys belong to authority objects outside ``MembraneShield``.
The shield receives only public verification keys and signed, scoped
capabilities. This module is intentionally transport-agnostic: callers may
carry capabilities over an authenticated channel or embed them in a request.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import Enum

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class Role(str, Enum):
    """Roles recognized by the authorization policy."""

    OBSERVATEUR = "observateur"
    CALIBRATEUR = "calibrateur"
    DECODEUR = "decodeur"
    GARDIEN = "gardien"


class Action(str, Enum):
    """Operations that can be authorized by a signed capability."""

    OBSERVE = "observe"
    WRITE = "write"
    CALIBRATE = "calibrate"


class AuthorizationError(ValueError):
    """Raised when a capability is malformed, invalid, expired, or replayed."""


@dataclass(frozen=True)
class SignedCapability:
    """A serialized authorization decision signed by one authority."""

    key_id: str
    subject: str
    role: Role
    action: Action
    request_id: str
    payload_digest: str
    issued_at: int
    expires_at: int
    signature: bytes

    def _unsigned_payload(self) -> bytes:
        fields = {
            "action": self.action.value,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "payload_digest": self.payload_digest,
            "request_id": self.request_id,
            "role": self.role.value,
            "subject": self.subject,
        }
        return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_bytes(self) -> bytes:
        """Serialize the signed capability without private key material."""

        fields = {
            "action": self.action.value,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "payload_digest": self.payload_digest,
            "request_id": self.request_id,
            "role": self.role.value,
            "signature": base64.urlsafe_b64encode(self.signature).decode("ascii"),
            "subject": self.subject,
        }
        return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> SignedCapability:
        """Parse a capability received from an untrusted transport."""

        try:
            fields = json.loads(data.decode("utf-8"))
            return cls(
                key_id=str(fields["key_id"]),
                subject=str(fields["subject"]),
                role=Role(fields["role"]),
                action=Action(fields["action"]),
                request_id=str(fields["request_id"]),
                payload_digest=str(fields["payload_digest"]),
                issued_at=int(fields["issued_at"]),
                expires_at=int(fields["expires_at"]),
                signature=base64.urlsafe_b64decode(fields["signature"].encode("ascii")),
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            binascii.Error,
        ) as exc:
            raise AuthorizationError("malformed signed capability") from exc


@dataclass(frozen=True)
class AuthorityKey:
    """Public identity needed by the shield-side verifier."""

    key_id: str
    role: Role
    public_key: bytes


class CapabilityIssuer:
    """Authority-side signer; keep the private key outside the shield process."""

    def __init__(self, key_id: str, subject: str, role: Role, private_key: Ed25519PrivateKey):
        if not key_id or not subject:
            raise ValueError("key_id and subject must be non-empty")
        if not isinstance(role, Role):
            raise ValueError("role must be a Role value")
        self.key_id = key_id
        self.subject = subject
        self.role = role
        self._private_key = private_key

    @classmethod
    def generate(cls, key_id: str, subject: str, role: Role) -> CapabilityIssuer:
        """Generate a new authority keypair outside the shield."""

        return cls(key_id, subject, role, Ed25519PrivateKey.generate())

    def authority_key(self) -> AuthorityKey:
        """Return only the public verification material for shield configuration."""

        public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return AuthorityKey(self.key_id, self.role, public_key)

    def issue(
        self,
        action: Action,
        payload: bytes = b"",
        *,
        request_id: str | None = None,
        now: int | None = None,
        lifetime_seconds: int = 60,
    ) -> SignedCapability:
        """Sign a narrowly scoped, short-lived capability."""

        if not isinstance(action, Action):
            raise ValueError("action must be an Action value")
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if not isinstance(lifetime_seconds, int) or lifetime_seconds < 1:
            raise ValueError("lifetime_seconds must be a positive integer")
        issued_at = int(time.time() if now is None else now)
        expires_at = issued_at + lifetime_seconds
        capability = SignedCapability(
            key_id=self.key_id,
            subject=self.subject,
            role=self.role,
            action=action,
            request_id=request_id or secrets.token_urlsafe(18),
            payload_digest=hashlib.sha256(payload).hexdigest(),
            issued_at=issued_at,
            expires_at=expires_at,
            signature=b"",
        )
        return replace(capability, signature=self._private_key.sign(capability._unsigned_payload()))


class CapabilityVerifier:
    """Shield-side verifier containing public keys but no signing secrets."""

    def __init__(
        self,
        authority_keys: Mapping[str, AuthorityKey],
        *,
        clock: Callable[[], int] | None = None,
        max_clock_skew_seconds: int = 5,
    ) -> None:
        if not authority_keys:
            raise ValueError("at least one authority key is required")
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self._keys = dict(authority_keys)
        self._clock = clock or (lambda: int(time.time()))
        self._max_clock_skew = max_clock_skew_seconds
        self._used_request_ids: set[str] = set()

    def verify(
        self,
        capability: SignedCapability,
        *,
        action: Action,
        role: Role,
        payload: bytes = b"",
        consume: bool = True,
    ) -> SignedCapability:
        """Verify scope, signature, time bounds, and optional one-time use."""

        if not isinstance(capability, SignedCapability):
            raise AuthorizationError("capability has invalid type")
        if capability.action is not action or capability.role is not role:
            raise AuthorizationError("capability scope mismatch")
        if capability.payload_digest != hashlib.sha256(payload).hexdigest():
            raise AuthorizationError("capability payload mismatch")
        authority = self._keys.get(capability.key_id)
        if authority is None or authority.role is not role:
            raise AuthorizationError("unknown authority key")
        now = int(self._clock())
        if capability.issued_at > now + self._max_clock_skew:
            raise AuthorizationError("capability issued in the future")
        if capability.expires_at <= now:
            raise AuthorizationError("capability expired")
        if capability.request_id in self._used_request_ids:
            raise AuthorizationError("capability replayed")
        try:
            Ed25519PublicKey.from_public_bytes(authority.public_key).verify(
                capability.signature, capability._unsigned_payload()
            )
        except (InvalidSignature, ValueError) as exc:
            raise AuthorizationError("invalid capability signature") from exc
        if consume:
            self._used_request_ids.add(capability.request_id)
        return capability

    def verify_independent_pair(
        self,
        first: SignedCapability,
        second: SignedCapability,
        *,
        action: Action,
        payload: bytes = b"",
    ) -> tuple[SignedCapability, SignedCapability]:
        """Verify two approvals from distinct roles, keys, and subjects."""

        if not isinstance(first, SignedCapability) or not isinstance(second, SignedCapability):
            raise AuthorizationError("dual-control approvals have invalid type")
        if (
            first.role is second.role
            or first.key_id == second.key_id
            or first.subject == second.subject
        ):
            raise AuthorizationError("dual control requires distinct authorities")
        self.verify(first, action=action, role=first.role, payload=payload, consume=False)
        self.verify(second, action=action, role=second.role, payload=payload, consume=False)
        self._used_request_ids.update((first.request_id, second.request_id))
        return first, second
