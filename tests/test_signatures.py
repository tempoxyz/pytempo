"""P256, WebAuthn and Keychain signatures against viem's tempo Accounts.

tests/testdata/viem/vectors.json is produced by viem's Account.fromP256,
Account.fromHeadlessWebAuthn, access keys and Account.signKeyAuthorization
(gen.mjs regenerates it). pytempo must reproduce every vector byte for byte.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from eth_utils import keccak, to_checksum_address

from pytempo import (
    Call,
    KeyAuthorization,
    KeychainSignature,
    SignedKeyAuthorization,
    TempoTransaction,
)
from pytempo.signatures import (
    KEY_TYPE_P256,
    KEY_TYPE_SECP256K1,
    KEY_TYPE_WEBAUTHN,
    P256_ORDER,
    InvalidSignatureError,
    P256Account,
    P256Signature,
    RecoveredSigner,
    Secp256k1Account,
    WebAuthnAccount,
    WebAuthnSignature,
    parse_primitive,
    parse_signature,
    recover_signer,
    webauthn_assertion,
    webauthn_message_hash,
)

V = json.loads(
    (Path(__file__).parent / "testdata" / "viem" / "vectors.json").read_text()
)
HASH = bytes.fromhex(V["hash"][2:])
ROOT = V["rootAddress"]


def h(value: str) -> bytes:
    return bytes.fromhex(value[2:])


@pytest.fixture
def p256() -> P256Account:
    return P256Account(V["p256Key"])


@pytest.fixture
def webauthn() -> WebAuthnAccount:
    return WebAuthnAccount(V["webAuthnKey"], rp_id=V["rpId"], origin=V["origin"])


class TestSignersMatchViem:
    def test_p256_account(self, p256: P256Account) -> None:
        assert p256.address == V["p256Address"]
        assert p256.public_key == h(V["p256PublicKey"])
        assert p256.sign_hash(HASH).to_bytes() == h(V["p256Signature"])

    def test_webauthn_account(self, webauthn: WebAuthnAccount) -> None:
        assert webauthn.address == V["webAuthnAddress"]
        assert webauthn.public_key == h(V["webAuthnPublicKey"])
        assert webauthn.sign_hash(HASH).to_bytes() == h(V["webAuthnSignature"])
        authenticator_data, client_data_json = webauthn_assertion(
            HASH, V["rpId"], V["origin"]
        )
        assert authenticator_data == h(V["webAuthnMetadata"]["authenticatorData"])
        assert client_data_json.decode() == V["webAuthnMetadata"]["clientDataJSON"]

    @pytest.mark.parametrize(
        ("key", "vector"),
        [
            ("p256", "p256AccessKeySignature"),
            ("webauthn", "webAuthnAccessKeySignature"),
        ],
    )
    def test_access_key_envelopes(
        self, key: str, vector: str, request: pytest.FixtureRequest
    ) -> None:
        account = request.getfixturevalue(key)
        sig = KeychainSignature.sign_with(HASH, account, ROOT)
        assert sig.to_bytes() == h(V[vector])
        assert KeychainSignature.from_bytes(h(V[vector])) == sig

    def test_keychain_v1_envelope(self, p256: P256Account) -> None:
        sig = KeychainSignature(
            root_account=ROOT, inner=p256.sign_hash(HASH), version=0x03
        )
        assert sig.to_bytes() == h(V["p256KeychainV1Signature"])


class TestRecoverEveryVector:
    @pytest.mark.parametrize(
        ("vector", "expected"),
        [
            ("p256Signature", (V["p256Address"], V["p256Address"], KEY_TYPE_P256, 0)),
            (
                "webAuthnSignature",
                (V["webAuthnAddress"], V["webAuthnAddress"], KEY_TYPE_WEBAUTHN, 0),
            ),
            ("p256AccessKeySignature", (ROOT, V["p256Address"], KEY_TYPE_P256, 0x04)),
            (
                "webAuthnAccessKeySignature",
                (ROOT, V["webAuthnAddress"], KEY_TYPE_WEBAUTHN, 0x04),
            ),
            ("p256KeychainV1Signature", (ROOT, V["p256Address"], KEY_TYPE_P256, 0x03)),
        ],
    )
    def test_recovers(self, vector: str, expected: tuple) -> None:
        assert recover_signer(HASH, h(V[vector])) == RecoveredSigner(*expected)
        assert parse_signature(h(V[vector])).to_bytes() == h(V[vector])
        with pytest.raises(InvalidSignatureError):
            recover_signer(keccak(b"other"), h(V[vector]))

    def test_keychain_v2_binds_the_user(self) -> None:
        envelope = bytearray(h(V["p256AccessKeySignature"]))
        envelope[1] ^= 0xFF
        with pytest.raises(InvalidSignatureError):
            recover_signer(HASH, bytes(envelope))

    def test_secp256k1(self) -> None:
        account = Secp256k1Account(V["rootKey"])
        sig = account.sign_hash(HASH)
        assert recover_signer(HASH, sig.to_bytes()) == RecoveredSigner(
            ROOT, ROOT, KEY_TYPE_SECP256K1, 0
        )
        envelope = KeychainSignature.sign_with(HASH, account, "0x" + "11" * 20)
        assert len(envelope.to_bytes()) == 86
        assert recover_signer(HASH, envelope.to_bytes()).key_id == ROOT
        legacy = KeychainSignature.sign(HASH, V["rootKey"], "0x" + "11" * 20)
        assert legacy.to_bytes() == envelope.to_bytes()

    def test_p256_pre_hash(self, p256: P256Account) -> None:
        r, s = p256.sign_digest(hashlib.sha256(HASH).digest())
        x, y = (
            int.from_bytes(p256.public_key[:32], "big"),
            int.from_bytes(p256.public_key[32:], "big"),
        )
        sig = P256Signature(r=r, s=s, pub_key_x=x, pub_key_y=y, pre_hash=True)
        assert recover_signer(HASH, sig.to_bytes()).account == V["p256Address"]
        with pytest.raises(InvalidSignatureError):
            recover_signer(
                HASH, P256Signature(r=r, s=s, pub_key_x=x, pub_key_y=y).to_bytes()
            )


def _mutate(raw: bytes, f) -> bytes:  # noqa: ANN001
    b = bytearray(raw)
    f(b)
    return bytes(b)


def _set(b: bytearray, start: int, end: int, value: bytes) -> None:
    b[start:end] = value


P256_SIG = h(V["p256Signature"])


@pytest.mark.parametrize(
    "envelope",
    [
        _mutate(
            P256_SIG,
            lambda b: _set(
                b,
                33,
                65,
                (P256_ORDER - int.from_bytes(b[33:65], "big")).to_bytes(32, "big"),
            ),
        ),
        _mutate(P256_SIG, lambda b: b.__setitem__(96, b[96] ^ 1)),
        _mutate(P256_SIG, lambda b: _set(b, 65, 129, bytes(64))),
        _mutate(P256_SIG, lambda b: _set(b, 65, 129, h(V["webAuthnPublicKey"]))),
        _mutate(P256_SIG, lambda b: _set(b, 1, 33, bytes(32))),
        P256_SIG[:129],
        P256_SIG + b"\x00",
        _mutate(P256_SIG, lambda b: b.__setitem__(0, 0x07)),
        b"",
        b"\x01",
    ],
    ids=[
        "high s",
        "off-curve key",
        "point at infinity",
        "another key",
        "zero r",
        "short",
        "long",
        "unknown type",
        "empty",
        "type byte only",
    ],
)
def test_rejects_invalid_p256(envelope: bytes) -> None:
    with pytest.raises(InvalidSignatureError):
        recover_signer(HASH, envelope)


def _webauthn(
    account: WebAuthnAccount, authenticator_data: bytes, client_data_json: bytes
) -> bytes:
    """Sign custom assertion data, so each rejection comes from the rule it names."""
    r, s = account.sign_digest(
        webauthn_message_hash(authenticator_data, client_data_json)
    )
    x, y = (
        int.from_bytes(account.public_key[:32], "big"),
        int.from_bytes(account.public_key[32:], "big"),
    )
    return WebAuthnSignature(
        webauthn_data=authenticator_data + client_data_json,
        r=r,
        s=s,
        pub_key_x=x,
        pub_key_y=y,
    ).to_bytes()


class TestWebAuthnRules:
    def _data(self) -> tuple[bytes, bytes, str]:
        authenticator_data, client_data_json = webauthn_assertion(
            HASH, V["rpId"], V["origin"]
        )
        challenge = json.loads(client_data_json)["challenge"]
        return authenticator_data, client_data_json, challenge

    def test_accepts(self, webauthn: WebAuthnAccount) -> None:
        auth, cdj, challenge = self._data()
        for flags in (0x01, 0x04, 0x05):
            data = auth[:32] + bytes([flags]) + auth[33:]
            assert (
                recover_signer(HASH, _webauthn(webauthn, data, cdj)).account
                == V["webAuthnAddress"]
            )
        extra = json.dumps(
            {"challenge": challenge, "type": "webauthn.get", "other": 1}
        ).encode()
        assert (
            recover_signer(HASH, _webauthn(webauthn, auth, extra)).account
            == V["webAuthnAddress"]
        )

    @pytest.mark.parametrize(
        "case",
        [
            "no user presence",
            "attested",
            "extensions",
            "create",
            "wrong challenge",
            "padded challenge",
            "not json",
            "oversized",
            "tampered",
            "short",
        ],
    )
    def test_rejects(self, webauthn: WebAuthnAccount, case: str) -> None:
        auth, cdj, challenge = self._data()
        with_flags = lambda flags: auth[:32] + bytes([flags]) + auth[33:]  # noqa: E731
        envelope = {
            "no user presence": lambda: _webauthn(webauthn, with_flags(0), cdj),
            "attested": lambda: _webauthn(webauthn, with_flags(0x41), cdj),
            "extensions": lambda: _webauthn(webauthn, with_flags(0x81), cdj),
            "create": lambda: _webauthn(
                webauthn,
                auth,
                json.dumps(
                    {"type": "webauthn.create", "challenge": challenge}
                ).encode(),
            ),
            "wrong challenge": lambda: _webauthn(
                webauthn, auth, b'{"type":"webauthn.get","challenge":"AAAA"}'
            ),
            "padded challenge": lambda: _webauthn(
                webauthn,
                auth,
                json.dumps(
                    {"type": "webauthn.get", "challenge": challenge + "="}
                ).encode(),
            ),
            "not json": lambda: _webauthn(
                webauthn, auth, b"not json, but long enough to pass the length checks"
            ),
            "oversized": lambda: _webauthn(webauthn, auth, cdj + bytes(2048)),
            "tampered": lambda: _mutate(
                h(V["webAuthnSignature"]), lambda b: b.__setitem__(60, b[60] ^ 1)
            ),
            "short": lambda: b"\x02" + bytes(127),
        }[case]()
        with pytest.raises(InvalidSignatureError):
            recover_signer(HASH, envelope)


def test_p256_signatures_are_deterministic_and_low_s(p256: P256Account) -> None:
    for i in range(128):
        digest = keccak(i.to_bytes(2, "big"))
        a, b = p256.sign_hash(digest), p256.sign_hash(digest)
        assert a == b
        assert a.s <= P256_ORDER // 2
        assert recover_signer(digest, a.to_bytes()).account == p256.address


def test_rejects_bad_p256_keys() -> None:
    for key in (0, P256_ORDER, "0x" + "00" * 32):
        with pytest.raises(ValueError):
            P256Account(key)


def test_origin_is_encoded_like_json_stringify() -> None:
    _, cdj = webauthn_assertion(bytes(32), "x", 'https://a.example/<&>"q"é')
    assert json.loads(cdj)["origin"] == 'https://a.example/<&>"q"é'
    assert "<&>" in cdj.decode() and "é" in cdj.decode()


class TestKeyAuthorizations:
    @pytest.mark.parametrize(
        ("key", "key_type", "vector"),
        [
            ("p256", KEY_TYPE_P256, "p256KeyAuthorization"),
            ("webauthn", KEY_TYPE_WEBAUTHN, "webAuthnKeyAuthorization"),
        ],
    )
    def test_matches_viem(
        self, key: str, key_type: int, vector: str, request: pytest.FixtureRequest
    ) -> None:
        account = request.getfixturevalue(key)
        auth = KeyAuthorization(
            key_id=account.address, chain_id=42431, key_type=key_type, expiry=4102444800
        )
        signed = auth.sign(V["rootKey"])
        assert signed.rlp_encode() == h(V[vector]["serialized"])
        assert (
            auth.sign_with(Secp256k1Account(V["rootKey"])).rlp_encode()
            == signed.rlp_encode()
        )
        assert (
            SignedKeyAuthorization.decode(signed.rlp_encode()).recover_signer() == ROOT
        )

    @pytest.mark.parametrize("key", ["p256", "webauthn"])
    def test_p256_and_webauthn_roots(
        self, key: str, request: pytest.FixtureRequest
    ) -> None:
        root = request.getfixturevalue(key)
        auth = KeyAuthorization(key_id="0x" + "22" * 20, chain_id=42431)
        signed = auth.sign_with(root)
        decoded = SignedKeyAuthorization.decode(signed.rlp_encode())
        assert decoded.signature == signed.signature
        assert decoded.recover_signer() == root.address
        assert decoded.to_json()["signature"]["type"] == (
            "p256" if key == "p256" else "webAuthn"
        )


def _viem_transaction(
    key_authorization: SignedKeyAuthorization | None = None,
) -> TempoTransaction:
    """The transaction gen.mjs signs."""
    return TempoTransaction.create(
        chain_id=42431,
        gas_limit=300000,
        max_fee_per_gas=20000000000,
        max_priority_fee_per_gas=1000000000,
        nonce=7,
        nonce_key=0,
        fee_token="0x20c0000000000000000000000000000000000000",
        calls=(
            Call.create(
                to="0x20c0000000000000000000000000000000000000",
                data="0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f1b0f200000000000000000000000000000000000000000000000000000000000f4240",
            ),
        ),
        key_authorization=key_authorization,
    )


class TestTransactionsMatchViem:
    @pytest.mark.parametrize(
        ("key", "vector"),
        [("p256", "p256RootTransaction"), ("webauthn", "webAuthnRootTransaction")],
    )
    def test_p256_and_webauthn_roots(
        self, key: str, vector: str, request: pytest.FixtureRequest
    ) -> None:
        account = request.getfixturevalue(key)
        tx = _viem_transaction()
        assert tx.get_signing_hash() == h(V[vector]["signPayload"])
        signed = tx.sign_with(account)
        assert "0x" + signed.encode().hex() == V[vector]["serialized"]
        assert signed.recover_signer() == RecoveredSigner(
            account.address, account.address, account.key_type, 0
        )

    def test_p256_access_key(self, p256: P256Account) -> None:
        auth = SignedKeyAuthorization.decode(h(V["p256KeyAuthorization"]["serialized"]))
        signed = _viem_transaction(auth).sign_access_key_with(p256, ROOT)
        assert (
            "0x" + signed.encode().hex() == V["p256AccessKeyTransaction"]["serialized"]
        )
        assert signed.recover_signer() == RecoveredSigner(
            ROOT, V["p256Address"], KEY_TYPE_P256, 0x04
        )

    def test_tampered_transaction_does_not_verify(self, p256: P256Account) -> None:
        import attrs

        signed = _viem_transaction().sign_with(p256)
        with pytest.raises(InvalidSignatureError):
            attrs.evolve(signed, nonce=8).recover_signer()


def test_parse_primitive_rejects_bad_layouts() -> None:
    for raw in (b"", b"\x01" + bytes(128), b"\x02" + bytes(2049), b"\x09" + bytes(129)):
        with pytest.raises(InvalidSignatureError):
            parse_primitive(raw)
    assert to_checksum_address(V["p256Address"]) == V["p256Address"]
