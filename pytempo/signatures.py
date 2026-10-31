"""P256, WebAuthn and Keychain signature envelopes.

Signs as viem's tempo Accounts do (``Account.fromP256``, ``Account.fromHeadlessWebAuthn`` and
access keys) and verifies any Tempo signature envelope as tempo-primitives
does (``TempoSignature::recover_signer``).

Envelopes:

- secp256k1: ``r || s || v`` (65 bytes, no type byte)
- P256: ``0x01 || r || s || pubKeyX || pubKeyY || preHash`` (130 bytes)
- WebAuthn: ``0x02 || authenticatorData || clientDataJSON || r || s || pubKeyX || pubKeyY``
- Keychain: ``0x03`` (V1) or ``0x04`` (V2) ``|| userAddress || inner``, where the
  inner signature is any of the above and, for V2, signs
  ``keccak256(0x04 || hash || userAddress)``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import ClassVar, NamedTuple, Protocol, Union

import attrs
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from .types import Address, BytesLike, as_address, as_bytes

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_HALF_ORDER = P256_ORDER // 2

SIGNATURE_TYPE_P256 = 0x01
SIGNATURE_TYPE_WEBAUTHN = 0x02
SIGNATURE_TYPE_KEYCHAIN_V1 = 0x03
SIGNATURE_TYPE_KEYCHAIN_V2 = 0x04

P256_SIGNATURE_LENGTH = 129  # r || s || x || y || preHash
MAX_WEBAUTHN_SIGNATURE_LENGTH = 2048
_MIN_AUTHENTICATOR_DATA = 37
_FLAG_UP, _FLAG_UV, _FLAG_AT, _FLAG_ED = 0x01, 0x04, 0x40, 0x80

KEY_TYPE_SECP256K1 = 0
KEY_TYPE_P256 = 1
KEY_TYPE_WEBAUTHN = 2


class InvalidSignatureError(ValueError):
    """A signature envelope is malformed or does not verify."""


def _int32(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _b32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _hex32(n: int) -> str:
    return "0x" + _b32(n).hex()


def _validate_scalar(instance: object, attribute: attrs.Attribute, value: int) -> None:
    if not 0 <= value < 2**256:
        raise ValueError(f"{attribute.name} must fit in 32 bytes")


@attrs.define(frozen=True)
class P256Signature:
    """A P256 signature with its public key (type ``0x01``).

    ``pre_hash`` marks a signature over ``sha256(hash)``, as WebCrypto keys sign.
    """

    TYPE_BYTE: ClassVar[int] = SIGNATURE_TYPE_P256

    r: int = attrs.field(validator=_validate_scalar)
    s: int = attrs.field(validator=_validate_scalar)
    pub_key_x: int = attrs.field(validator=_validate_scalar)
    pub_key_y: int = attrs.field(validator=_validate_scalar)
    pre_hash: bool = False

    def to_bytes(self) -> bytes:
        return (
            bytes([self.TYPE_BYTE])
            + _b32(self.r)
            + _b32(self.s)
            + _b32(self.pub_key_x)
            + _b32(self.pub_key_y)
            + bytes([int(self.pre_hash)])
        )

    @property
    def public_key(self) -> bytes:
        """The 64-byte public key ``x || y``."""
        return _b32(self.pub_key_x) + _b32(self.pub_key_y)

    def to_json(self) -> dict:
        """The JSON-RPC form, as ox's ``SignatureEnvelope.toRpc``."""
        return {
            "type": "p256",
            "r": _hex32(self.r),
            "s": _hex32(self.s),
            "pubKeyX": _hex32(self.pub_key_x),
            "pubKeyY": _hex32(self.pub_key_y),
            "preHash": self.pre_hash,
        }


@attrs.define(frozen=True)
class WebAuthnSignature:
    """A WebAuthn assertion signature (type ``0x02``).

    ``webauthn_data`` is ``authenticatorData || clientDataJSON``.
    """

    TYPE_BYTE: ClassVar[int] = SIGNATURE_TYPE_WEBAUTHN

    webauthn_data: bytes = attrs.field(converter=as_bytes)
    r: int = attrs.field(validator=_validate_scalar)
    s: int = attrs.field(validator=_validate_scalar)
    pub_key_x: int = attrs.field(validator=_validate_scalar)
    pub_key_y: int = attrs.field(validator=_validate_scalar)

    def to_bytes(self) -> bytes:
        return (
            bytes([self.TYPE_BYTE])
            + self.webauthn_data
            + _b32(self.r)
            + _b32(self.s)
            + _b32(self.pub_key_x)
            + _b32(self.pub_key_y)
        )

    @property
    def public_key(self) -> bytes:
        """The 64-byte public key ``x || y``."""
        return _b32(self.pub_key_x) + _b32(self.pub_key_y)

    def to_json(self) -> dict:
        """The JSON-RPC form, as ox's ``SignatureEnvelope.toRpc``."""
        return {
            "type": "webAuthn",
            "r": _hex32(self.r),
            "s": _hex32(self.s),
            "pubKeyX": _hex32(self.pub_key_x),
            "pubKeyY": _hex32(self.pub_key_y),
            "webauthnData": "0x" + self.webauthn_data.hex(),
        }


class RecoveredSigner(NamedTuple):
    """The signer of a verified signature envelope."""

    account: str
    """The account the signature acts for (checksummed): the signer of a
    primitive signature, or a Keychain envelope's user address."""
    key_id: str
    """The key that signed (checksummed): ``account`` for a primitive signature, or
    the access key inside a Keychain envelope."""
    key_type: int
    """The signing key's type: 0 secp256k1, 1 P256, 2 WebAuthn."""
    keychain: int
    """0 for a primitive signature, or 0x03 / 0x04 for a Keychain envelope."""


def p256_address(public_key: bytes) -> str:
    """The account of a P256 public key ``x || y``: ``keccak256(x || y)[12:]``."""
    if len(public_key) != 64:
        raise ValueError("P256 public key must be 64 bytes (x || y)")
    return to_checksum_address(keccak(public_key)[12:])


def keychain_v2_hash(msg_hash: bytes, user: BytesLike) -> bytes:
    """The digest a Keychain V2 access key signs: ``keccak256(0x04 || hash || user)``."""
    return keccak(
        bytes([SIGNATURE_TYPE_KEYCHAIN_V2]) + msg_hash + bytes(as_address(user))
    )


def webauthn_assertion(
    challenge: bytes, rp_id: str, origin: str
) -> tuple[bytes, bytes]:
    """The authenticator data and clientDataJSON a headless WebAuthn signer
    produces for ``challenge``, byte for byte as ox's ``WebAuthnP256.getSignPayload``:
    ``sha256(rpId) || 0x05 || counter 0``, and
    ``{"type":"webauthn.get","challenge":...,"origin":...,"crossOrigin":false}``.
    """
    authenticator_data = hashlib.sha256(rp_id.encode()).digest() + bytes(
        [_FLAG_UP | _FLAG_UV, 0, 0, 0, 0]
    )
    client_data_json = (
        '{"type":"webauthn.get","challenge":"'
        + _b64url(challenge)
        + '","origin":'
        + json.dumps(origin, ensure_ascii=False)
        + ',"crossOrigin":false}'
    ).encode()
    return authenticator_data, client_data_json


def webauthn_message_hash(authenticator_data: bytes, client_data_json: bytes) -> bytes:
    """``sha256(authenticatorData || sha256(clientDataJSON))``, the digest a WebAuthn key signs."""
    return hashlib.sha256(
        authenticator_data + hashlib.sha256(client_data_json).digest()
    ).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class _Prehashed:
    """A hash object carrying a precomputed SHA-256-sized digest, so DSS signs
    and verifies the digest itself (RFC 6979 nonces still use SHA-256)."""

    def __init__(self, digest: bytes) -> None:
        from Crypto.Hash import SHA256

        self._digest = digest
        self.oid = SHA256.new().oid
        self.digest_size = 32
        self.block_size = 64

    def digest(self) -> bytes:
        return self._digest

    def new(self, data: bytes | None = None):  # noqa: ANN201
        from Crypto.Hash import SHA256

        return SHA256.new(data)


class P256Account:
    """A P-256 key that signs as viem's ``Account.fromP256``: RFC 6979
    deterministic, low-s signatures over the hash itself."""

    key_type: ClassVar[int] = KEY_TYPE_P256

    def __init__(self, private_key: BytesLike | int) -> None:
        from Crypto.PublicKey import ECC

        d = (
            private_key
            if isinstance(private_key, int)
            else _int32(as_bytes(private_key))
        )
        if not 0 < d < P256_ORDER:
            raise ValueError("invalid P256 private key")
        self._key = ECC.construct(curve="P-256", d=d)
        self.public_key = _b32(int(self._key.pointQ.x)) + _b32(int(self._key.pointQ.y))
        self.address = p256_address(self.public_key)

    def sign_digest(self, digest: bytes) -> tuple[int, int]:
        """Sign a 32-byte digest; returns low-s ``(r, s)``."""
        from Crypto.Signature import DSS

        if len(digest) != 32:
            raise ValueError("P256 digest must be 32 bytes")
        sig = DSS.new(self._key, "deterministic-rfc6979").sign(_Prehashed(digest))
        r, s = _int32(sig[:32]), _int32(sig[32:])
        return r, (P256_ORDER - s if s > P256_HALF_ORDER else s)

    def sign_hash(self, msg_hash: bytes) -> P256Signature:
        """Sign a 32-byte hash as viem's ``Account.fromP256``."""
        r, s = self.sign_digest(msg_hash)
        x, y = _int32(self.public_key[:32]), _int32(self.public_key[32:])
        return P256Signature(r=r, s=s, pub_key_x=x, pub_key_y=y)


class WebAuthnAccount(P256Account):
    """A headless WebAuthn credential, as viem's ``Account.fromHeadlessWebAuthn``:
    the assertion's challenge is the hash being signed."""

    key_type: ClassVar[int] = KEY_TYPE_WEBAUTHN

    def __init__(
        self, private_key: BytesLike | int, *, rp_id: str, origin: str
    ) -> None:
        super().__init__(private_key)
        self.rp_id = rp_id
        self.origin = origin

    def sign_hash(self, msg_hash: bytes) -> WebAuthnSignature:  # type: ignore[override]
        """Sign a 32-byte hash as a WebAuthn assertion."""
        authenticator_data, client_data_json = webauthn_assertion(
            msg_hash, self.rp_id, self.origin
        )
        if (
            len(authenticator_data) + len(client_data_json) + 128
            > MAX_WEBAUTHN_SIGNATURE_LENGTH
        ):
            raise ValueError(
                f"WebAuthn assertion exceeds {MAX_WEBAUTHN_SIGNATURE_LENGTH} bytes"
                " (origin too long)"
            )
        r, s = self.sign_digest(
            webauthn_message_hash(authenticator_data, client_data_json)
        )
        x, y = _int32(self.public_key[:32]), _int32(self.public_key[32:])
        return WebAuthnSignature(
            webauthn_data=authenticator_data + client_data_json,
            r=r,
            s=s,
            pub_key_x=x,
            pub_key_y=y,
        )


class EnvelopeSigner(Protocol):
    """Anything that signs a hash into a primitive Tempo signature."""

    address: str
    key_type: int

    def sign_hash(self, msg_hash: bytes) -> PrimitiveSignature: ...


class Secp256k1Account:
    """A secp256k1 key as an :class:`EnvelopeSigner`."""

    key_type: ClassVar[int] = KEY_TYPE_SECP256K1

    def __init__(self, private_key: str) -> None:
        self._account = Account.from_key(private_key)
        self.address = self._account.address

    def sign_hash(self, msg_hash: bytes):  # noqa: ANN201
        from .models import Signature

        signed = self._account.unsafe_sign_hash(msg_hash)
        return Signature(r=signed.r, s=signed.s, v=signed.v)


PrimitiveSignature = Union["Signature", P256Signature, WebAuthnSignature]  # noqa: F821


def parse_primitive(raw: BytesLike) -> PrimitiveSignature:
    """Parse a primitive signature envelope (layout only; not verified).

    Raises:
        InvalidSignatureError: If the envelope is malformed.
    """
    from .models import Signature

    b = as_bytes(raw)
    if len(b) == 65:
        try:
            return Signature.from_bytes(b)
        except ValueError as error:
            raise InvalidSignatureError(
                f"invalid secp256k1 signature: {error}"
            ) from error
    if len(b) < 2:
        raise InvalidSignatureError("signature envelope is too short")
    data = b[1:]
    if b[0] == SIGNATURE_TYPE_P256:
        if len(data) != P256_SIGNATURE_LENGTH:
            raise InvalidSignatureError(f"invalid P256 signature length {len(b)}")
        return P256Signature(
            r=_int32(data[0:32]),
            s=_int32(data[32:64]),
            pub_key_x=_int32(data[64:96]),
            pub_key_y=_int32(data[96:128]),
            pre_hash=data[128] != 0,
        )
    if b[0] == SIGNATURE_TYPE_WEBAUTHN:
        if not 128 <= len(data) <= MAX_WEBAUTHN_SIGNATURE_LENGTH:
            raise InvalidSignatureError(f"invalid WebAuthn signature length {len(b)}")
        sig = data[-128:]
        return WebAuthnSignature(
            webauthn_data=data[:-128],
            r=_int32(sig[0:32]),
            s=_int32(sig[32:64]),
            pub_key_x=_int32(sig[64:96]),
            pub_key_y=_int32(sig[96:128]),
        )
    raise InvalidSignatureError(f"unknown signature type {b[0]:#04x}")


def parse_signature(raw: BytesLike):  # noqa: ANN201
    """Parse any Tempo signature envelope: a primitive signature or a
    :class:`~pytempo.KeychainSignature` (layout only; not verified)."""
    from .keychain import KeychainSignature

    b = as_bytes(raw)
    if (
        len(b) > 21
        and len(b) != 65
        and b[0] in (SIGNATURE_TYPE_KEYCHAIN_V1, SIGNATURE_TYPE_KEYCHAIN_V2)
    ):
        try:
            return KeychainSignature.from_bytes(b)
        except InvalidSignatureError:
            raise
        except ValueError as error:
            raise InvalidSignatureError(
                f"invalid keychain signature: {error}"
            ) from error
    return parse_primitive(b)


def recover_primitive(
    msg_hash: bytes, signature: PrimitiveSignature | BytesLike
) -> tuple[str, int]:
    """Verify a primitive signature over ``msg_hash`` and return its signer
    (checksummed) and key type.

    Raises:
        InvalidSignatureError: If the signature is malformed or does not verify.
    """
    from .models import Signature

    sig = (
        signature
        if isinstance(signature, (Signature, P256Signature, WebAuthnSignature))
        else parse_primitive(signature)
    )
    if len(msg_hash) != 32:
        raise InvalidSignatureError("hash must be 32 bytes")
    if isinstance(sig, Signature):
        v = sig.v - 27 if sig.v >= 27 else sig.v
        try:
            signer = Account._recover_hash(msg_hash, vrs=(v + 27, sig.r, sig.s))
        except Exception as error:
            raise InvalidSignatureError(
                f"invalid secp256k1 signature: {error}"
            ) from error
        return to_checksum_address(signer), KEY_TYPE_SECP256K1
    if isinstance(sig, P256Signature):
        digest = hashlib.sha256(msg_hash).digest() if sig.pre_hash else msg_hash
        return _verify_p256(digest, sig.r, sig.s, sig.public_key), KEY_TYPE_P256
    digest = _webauthn_message(sig.webauthn_data, msg_hash)
    return _verify_p256(digest, sig.r, sig.s, sig.public_key), KEY_TYPE_WEBAUTHN


def recover_signer(msg_hash: bytes, envelope) -> RecoveredSigner:  # noqa: ANN001
    """Verify any Tempo signature envelope over ``msg_hash`` and return its signer,
    as tempo-primitives' ``TempoSignature::recover_signer`` does.

    For a Keychain envelope this only proves that ``key_id`` signed for
    ``account``: whether the account authorized the key is on-chain state (the
    AccountKeychain precompile) callers must check.

    Raises:
        InvalidSignatureError: If the envelope is malformed or does not verify.
    """
    from .keychain import KeychainSignature

    sig = (
        parse_signature(envelope)
        if isinstance(envelope, (bytes, bytearray, str))
        else envelope
    )
    if isinstance(sig, KeychainSignature):
        user = bytes(sig.root_account)
        inner_hash = keychain_v2_hash(msg_hash, user) if sig.version == 2 else msg_hash
        key_id, key_type = recover_primitive(inner_hash, sig.inner)
        return RecoveredSigner(
            to_checksum_address(user), key_id, key_type, sig.type_byte
        )
    signer, key_type = recover_primitive(msg_hash, sig)
    return RecoveredSigner(signer, signer, key_type, 0)


def _verify_p256(digest: bytes, r: int, s: int, public_key: bytes) -> str:
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS

    if s > P256_HALF_ORDER:
        raise InvalidSignatureError("P256 signature has high s")
    if not (0 < r < P256_ORDER and 0 < s < P256_ORDER):
        raise InvalidSignatureError("P256 signature is out of range")
    x, y = _int32(public_key[:32]), _int32(public_key[32:])
    try:
        key = ECC.construct(curve="P-256", point_x=x, point_y=y)
    except ValueError as error:
        raise InvalidSignatureError("invalid P256 public key") from error
    # pycryptodome reads (0, 0) as the point at infinity, which every
    # signature would verify against; Tempo rejects it as an invalid key.
    if key.pointQ.is_point_at_infinity():
        raise InvalidSignatureError("invalid P256 public key")
    try:
        DSS.new(key, "fips-186-3").verify(_Prehashed(digest), _b32(r) + _b32(s))
    except ValueError as error:
        raise InvalidSignatureError("P256 signature verification failed") from error
    return p256_address(public_key)


class _Borrowable(str):
    """A JSON string value without escapes, which serde can borrow."""


class _Pairs(list):
    """A JSON object's key/value pairs, in order, duplicates kept."""


def _has_surrogates(value: str) -> bool:
    """Whether a decoded JSON string holds a surrogate: an invalid UTF-8 byte
    (kept by ``surrogateescape``) or a lone ``\\ud800``-``\\udfff`` escape,
    neither of which serde accepts in the keys and fields it parses."""
    return any("\ud800" <= ch <= "\udfff" for ch in value)


def _ascii_number(parse):  # noqa: ANN001, ANN202
    """Wrap a JSON number parser: Python's scanner matches any Unicode digit
    (its number pattern uses ``\\d``), but JSON and serde allow only ASCII."""

    def checked(text: str):  # noqa: ANN202
        if not text.isascii():
            raise ValueError(f"{text!r} is not a valid JSON number")
        return parse(text)

    return checked


def _parse_client_data(raw: bytes) -> tuple[str, str]:
    """Read ``type`` and ``challenge`` from a clientDataJSON exactly as
    tempo-primitives' serde struct does: a JSON object with valid UTF-8 keys
    (or the two-element array serde also reads), field names matched exactly,
    unknown fields ignored (and not UTF-8 validated), each field present once,
    and both values plain strings without escapes.
    """
    from json import scanner
    from json.decoder import JSONDecoder, scanstring

    # serde does not UTF-8 validate ignored values: keep invalid bytes as
    # surrogates and reject them only in keys and in the two fields.
    text = raw.decode("utf-8", errors="surrogateescape")

    def parse_string(s: str, end: int, strict: bool = True) -> tuple[str, int]:
        value, new_end = scanstring(s, end, strict)
        if "\\" not in s[end : new_end - 1] and not _has_surrogates(value):
            return _Borrowable(value), new_end
        return value, new_end

    def reject_constant(name: str) -> None:
        raise ValueError(f"{name} is not valid JSON")

    def object_pairs(pairs: list[tuple[str, object]]) -> _Pairs:
        for key, _ in pairs:
            if _has_surrogates(key):
                raise ValueError("a key is not valid UTF-8")
        return _Pairs(pairs)

    decoder = JSONDecoder(
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
        parse_int=_ascii_number(int),
        parse_float=_ascii_number(float),
    )
    decoder.parse_string = parse_string  # type: ignore[attr-defined]
    decoder.scan_once = scanner.py_make_scanner(decoder)  # type: ignore[attr-defined]
    try:
        parsed = decoder.decode(text)
        if isinstance(parsed, _Pairs):
            fields: dict[str, object] = {}
            for key, value in parsed:
                if key in ("type", "challenge"):
                    if key in fields:
                        raise ValueError(f"duplicate {key} field")
                    fields[key] = value
            if "type" not in fields or "challenge" not in fields:
                raise ValueError("missing type or challenge field")
            values = (fields["type"], fields["challenge"])
        elif isinstance(parsed, list):
            if len(parsed) != 2:
                raise ValueError("array must hold exactly the type and challenge")
            values = (parsed[0], parsed[1])
        else:
            raise ValueError("is not a JSON object")
    except (ValueError, RecursionError) as error:
        raise InvalidSignatureError(f"clientDataJSON is invalid: {error}") from error
    for value in values:
        if not isinstance(value, _Borrowable):
            raise InvalidSignatureError(
                "clientDataJSON type and challenge must be strings without escapes"
            )
    return str(values[0]), str(values[1])


def _webauthn_message(data: bytes, challenge: bytes) -> bytes:
    """Validate WebAuthn assertion data for ``challenge`` as Tempo does and
    return the digest its key signed."""
    if len(data) < _MIN_AUTHENTICATOR_DATA + 32:
        raise InvalidSignatureError("WebAuthn data is too short")
    flags = data[32]
    if not flags & (_FLAG_UP | _FLAG_UV):
        raise InvalidSignatureError("WebAuthn user presence flag is not set")
    if flags & _FLAG_AT:
        raise InvalidSignatureError("WebAuthn assertion has attested credential data")
    if flags & _FLAG_ED:
        raise InvalidSignatureError("WebAuthn extensions are not supported")
    authenticator_data = data[:_MIN_AUTHENTICATOR_DATA]
    client_data_json = data[_MIN_AUTHENTICATOR_DATA:]
    client_type, client_challenge = _parse_client_data(client_data_json)
    if client_type != "webauthn.get":
        raise InvalidSignatureError("clientDataJSON type must be webauthn.get")
    if client_challenge != _b64url(challenge):
        raise InvalidSignatureError("WebAuthn challenge does not match")
    return webauthn_message_hash(authenticator_data, client_data_json)


__all__ = [
    "Address",
    "EnvelopeSigner",
    "InvalidSignatureError",
    "KEY_TYPE_P256",
    "KEY_TYPE_SECP256K1",
    "KEY_TYPE_WEBAUTHN",
    "P256Account",
    "P256Signature",
    "RecoveredSigner",
    "Secp256k1Account",
    "WebAuthnAccount",
    "WebAuthnSignature",
    "keychain_v2_hash",
    "p256_address",
    "parse_primitive",
    "parse_signature",
    "recover_primitive",
    "recover_signer",
    "webauthn_assertion",
    "webauthn_message_hash",
]
