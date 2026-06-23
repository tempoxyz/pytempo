"""Typed helpers for the SignatureVerifier precompile (TIP-1020).

Verify secp256k1, P256, and WebAuthn signatures on-chain via the canonical
SignatureVerifier precompile at :data:`SIGNATURE_VERIFIER_ADDRESS`.

::

    from pytempo.contracts import SignatureVerifier

    signer = SignatureVerifier.recover(w3, hash=digest, signature=sig)
    ok = SignatureVerifier.verify(w3, signer=addr, hash=digest, signature=sig)

.. note::
    T6 (TIP-1049) adds stateful keychain helpers ``verifyKeychain`` and
    ``verifyKeychainAdmin`` to this precompile. They are not yet exposed in the
    ``tempo-std`` ``ISignatureVerifier`` interface, so they are intentionally
    omitted here until the interface ships them (keeping vendored ABIs in sync).
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
