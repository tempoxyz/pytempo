"""Typed helpers for the SignatureVerifier precompile (TIP-1020).

Verify secp256k1, P256, and WebAuthn signatures on-chain via the canonical
SignatureVerifier precompile at :data:`SIGNATURE_VERIFIER_ADDRESS`.

::

    from pytempo.contracts import SignatureVerifier

    signer = SignatureVerifier.recover(w3, hash=digest, signature=sig)
    ok = SignatureVerifier.verify(w3, signer=addr, hash=digest, signature=sig)

T6 (TIP-1049) adds stateful keychain helpers that validate a signature against an
account's live ``AccountKeychain`` state::

    ok = SignatureVerifier.verify_keychain(w3, account=acct, hash=digest, signature=sig)
    ok = SignatureVerifier.verify_keychain_admin(w3, account=acct, hash=digest, signature=sig)

Both require a **V2 keychain signature envelope** (``0x04 || account || inner``),
not a raw 65-byte signature, and the embedded address must equal ``account``.
They differ in which keys count as valid:

- :meth:`verify_keychain` — an active access key (admin or non-admin). The root
  key alone is **not** accepted.
- :meth:`verify_keychain_admin` — the account's root key **or** an active admin
  access key. Non-admin access keys are rejected.

When asking a user or key to sign a digest for :meth:`verify_keychain_admin`,
domain-separate it with replay context (chain id, verifying contract, account,
the specific action/purpose, and a nonce and/or deadline) so an admin proof
cannot be replayed for a different action.
"""

from __future__ import annotations

from ..types import BytesLike, as_bytes, as_hash32
from ._decode import decode_address, decode_bool
from ._encode import encode_calldata
from .abis import SIGNATURE_VERIFIER_ABI
from .addresses import SIGNATURE_VERIFIER_ADDRESS

_ABI = SIGNATURE_VERIFIER_ABI


class SignatureVerifier:
    """SignatureVerifier precompile read helpers.

    All methods target the precompile at :data:`SIGNATURE_VERIFIER_ADDRESS`.
    """

    ADDRESS = SIGNATURE_VERIFIER_ADDRESS

    @staticmethod
    def recover(w3, *, hash: BytesLike, signature: BytesLike) -> str:
        """Recover the signer address for ``hash`` and ``signature``."""
        call_data = encode_calldata(
            _ABI, "recover", [as_hash32(hash), as_bytes(signature)]
        )
        result = w3.eth.call({"to": SIGNATURE_VERIFIER_ADDRESS, "data": call_data})
        return decode_address(result, "recover")

    @staticmethod
    def verify(
        w3,
        *,
        signer: str,
        hash: BytesLike,
        signature: BytesLike,
    ) -> bool:
        """Return whether ``signature`` over ``hash`` is valid for ``signer``."""
        if not signer:
            raise ValueError("signer required")
        call_data = encode_calldata(
            _ABI, "verify", [signer, as_hash32(hash), as_bytes(signature)]
        )
        result = w3.eth.call({"to": SIGNATURE_VERIFIER_ADDRESS, "data": call_data})
        return decode_bool(result, "verify")

    @staticmethod
    def verify_keychain(
        w3,
        *,
        account: str,
        hash: BytesLike,
        signature: BytesLike,
    ) -> bool:
        """Return whether ``signature`` over ``hash`` is from an active access key of ``account``.

        T6 (TIP-1049) stateful check: requires a V2 keychain envelope whose
        embedded address equals ``account``, and returns ``True`` only if the
        recovered key is an active access key (admin or non-admin) for
        ``account``. The root key alone does **not** satisfy this check; use
        :meth:`verify_keychain_admin` for root/admin semantics.
        """
        if not account:
            raise ValueError("account required")
        call_data = encode_calldata(
            _ABI, "verifyKeychain", [account, as_hash32(hash), as_bytes(signature)]
        )
        result = w3.eth.call({"to": SIGNATURE_VERIFIER_ADDRESS, "data": call_data})
        return decode_bool(result, "verifyKeychain")

    @staticmethod
    def verify_keychain_admin(
        w3,
        *,
        account: str,
        hash: BytesLike,
        signature: BytesLike,
    ) -> bool:
        """Return whether ``signature`` over ``hash`` is from the root or an admin key of ``account``.

        T6 (TIP-1049) stateful check with "root key or admin key of this account
        signed this" semantics: requires a V2 keychain envelope whose embedded
        address equals ``account``, and returns ``True`` for the account's root
        key or an active admin access key (non-admin access keys are rejected).

        The ``account`` is **not** bound into ``hash``; callers should
        domain-separate the signed digest with replay context (chain id,
        verifying contract, account, action/purpose, and a nonce and/or
        deadline) to prevent admin-proof replay.
        """
        if not account:
            raise ValueError("account required")
        call_data = encode_calldata(
            _ABI,
            "verifyKeychainAdmin",
            [account, as_hash32(hash), as_bytes(signature)],
        )
        result = w3.eth.call({"to": SIGNATURE_VERIFIER_ADDRESS, "data": call_data})
        return decode_bool(result, "verifyKeychainAdmin")
