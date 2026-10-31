"""Tests for TempoTransaction.decode and sender / fee payer recovery.

Vectors come from the cross-SDK conformance suite (tempoxyz/mpp-tools
tempo-conformance/vectors/decode.json); their expected senders, fee payers and
hashes are the ones tempo-primitives and the Tempo node report.
"""

import attrs
import pytest
import rlp
from eth_account import Account
from eth_utils import keccak

from pytempo import (
    AccessListItem,
    Call,
    KeyAuthorization,
    KeychainSignature,
    Signature,
    TempoTransaction,
    TokenLimit,
)
from pytempo.models import SECP256K1_N

TRANSFER = bytes.fromhex(
    "a9059cbb"
    "000000000000000000000000000000000000000000000000000000000000beef"
    "0000000000000000000000000000000000000000000000000000000000000001"
)
PATH_USD = "0x20c0000000000000000000000000000000000000"

DECODE_MINIMAL = bytes.fromhex(
    "76f8bd820539843b9aca00850ba43b7400831e8480f85ef85c9420c00000000000000000"
    "0000000000000000000080b844a9059cbb00000000000000000000000000000000000000"
    "0000000000000000000000beef0000000000000000000000000000000000000000000000"
    "000000000000000001c0808080808080c0b8419c7591b4d27edfaa28c23c04e883d86a2f"
    "86a728958e9af78423f6b05a28b6ba3b1197c2e7f5cd97828183433f919140c18f8db561"
    "db7e343e3d01305405dc091c"
)
DECODE_KEYCHAIN_SPONSORED = bytes.fromhex(
    "76f90116820539843b9aca00850ba43b7400831e8480f85ef85c9420c000000000000000"
    "000000000000000000000080b844a9059cbb000000000000000000000000000000000000"
    "000000000000000000000000beef00000000000000000000000000000000000000000000"
    "00000000000000000001c08002808080f84301a0ded00ff03611df11242232dedb01a9b2"
    "ec4d2f3444811267c158f1eb64363bd6a041ed588851c691bda6f3736c7cecf50eed4871"
    "46bddc3b2a964dec921ca40c03c0b8560470505783416ca25a9b3bd1334da28240883f3c"
    "3bfc6e5728a566033784f37000d22a747d4f91b58341b368b4fd1ec378b8df8a0806532a"
    "d0c6ea4ecf28608df3b26d5f2156afbc727333a7c74fe71c4e0debf6ea1c"
)
DECODE_KA_EXPIRY_PERIODIC_LIMIT = bytes.fromhex(
    "76f90141820539843b9aca00850ba43b7400831e8480f85ef85c9420c000000000000000"
    "000000000000000000000080b844a9059cbb000000000000000000000000000000000000"
    "000000000000000000000000beef00000000000000000000000000000000000000000000"
    "00000000000000000001c0808080808080c0f882f83d820539809480abf92f6b72752d38"
    "47873a704bdb11c033c9a584f4865700dedd9420c0000000000000000000000000000000"
    "000000834c4b4083015180b841650493a5c44f0e6595259a5d7b911ead832a6a2bca31bc"
    "4cb4b934017c4194d657b730348fe748153c49eff585e71952d320f09b97f8ecf3734efe"
    "2fb2c728b31cb841ea50fa1e7165fbd7ae19861ac01acfea18790aaa5799aafbcb7a16a9"
    "134a9d736fbafe21f3f97b35a4d9813ec5a87f93dd7f0ee4ff48db9d4d61ca3bbba9841f"
    "1c"
)
# Legacy tempo.ts fee payer format: RLP + sender + feefeefeefee trailer.
TEMPO_TS_FEE_PAYER_TRAILER = bytes.fromhex(
    "76f87582a5bd808502cb417800825dc2dcdb940000000000000000000000000000000000"
    "0000008084deadbeefc0800b80808000c0b8417607a2e7bea757dc38093db971a7ec7537"
    "a690a698119d629b2eb6bb433315767a20aeb717b10285986bc22f0cbb7e9254a2a1f35d"
    "5c29ad5119e8b46e202ec401d47b37bbc34fa57e9a67ae7d0a1496edc88f04bbfeefeefe"
    "efee"
)

SENDER_KEY = "0x" + "11" * 32
FEE_PAYER_KEY = "0x" + "22" * 32
ACCESS_KEY = "0x" + "33" * 32
ROOT_KEY = "0x" + "44" * 32


def _addr(key: str) -> str:
    return Account.from_key(key).address


def _base_tx(**overrides) -> TempoTransaction:
    fields = {
        "chain_id": 1337,
        "gas_limit": 2_000_000,
        "max_fee_per_gas": 50_000_000_000,
        "max_priority_fee_per_gas": 1_000_000_000,
        "calls": (Call.create(to=PATH_USD, data=TRANSFER),),
    }
    fields.update(overrides)
    return TempoTransaction.create(**fields)


def _fields(raw: bytes) -> list:
    assert raw[0] == 0x76
    return rlp.decode(raw[1:])


def _raw(fields: list) -> bytes:
    return b"\x76" + rlp.encode(fields)


class TestDecodeVectors:
    def test_minimal(self):
        tx = TempoTransaction.decode(DECODE_MINIMAL)
        assert tx.chain_id == 1337
        assert tx.nonce == 0 and tx.nonce_key == 0
        assert tx.gas_limit == 2_000_000
        assert tx.max_fee_per_gas == 50_000_000_000
        assert tx.max_priority_fee_per_gas == 1_000_000_000
        assert tx.calls == (Call.create(to=PATH_USD, data=TRANSFER),)
        assert tx.access_list == ()
        assert tx.valid_before is None and tx.valid_after is None
        assert tx.fee_token is None and tx.key_authorization is None
        assert isinstance(tx.sender_signature, Signature)
        assert (
            bytes(tx.sender_address).hex() == "0e6fd5d3582d21c6abf24d21987e11d8ceeb6098"
        )
        assert tx.recover_fee_payer() is None
        assert tx.hash().hex() == (
            "1b00458c44cae1b4231552d4dc9cc7e97ce569bd593338dfadaccdee7ff384e6"
        )

    def test_accepts_hex_string(self):
        assert TempoTransaction.decode("0x" + DECODE_MINIMAL.hex()) == (
            TempoTransaction.decode(DECODE_MINIMAL)
        )

    def test_keychain_sponsored(self):
        tx = TempoTransaction.decode(DECODE_KEYCHAIN_SPONSORED)
        assert isinstance(tx.sender_signature, KeychainSignature)
        assert tx.sender_signature.version == 2
        assert (
            bytes(tx.sender_address).hex() == "70505783416ca25a9b3bd1334da28240883f3c3b"
        )
        assert tx.recover_fee_payer().lower() == (
            "0x1f6b696587342f9b5a6816fa7df990f37719667b"
        )
        assert tx.hash().hex() == (
            "d066c9314285fa5cc29591999e995220ede1a3a2a23da5c667ee6ac7eb40f11a"
        )

    def test_key_authorization_with_periodic_limit(self):
        tx = TempoTransaction.decode(DECODE_KA_EXPIRY_PERIODIC_LIMIT)
        auth = tx.key_authorization.authorization
        assert auth.chain_id == 1337
        assert bytes(auth.key_id).hex() == "80abf92f6b72752d3847873a704bdb11c033c9a5"
        assert auth.expiry == 4102444800
        assert auth.limits == (
            TokenLimit(token=PATH_USD, limit=5_000_000, period=86400),
        )
        assert (
            bytes(tx.sender_address).hex() == "123f68c947a95a862624b693981adbc31c804922"
        )
        assert tx.hash().hex() == (
            "8afae595150ebf590188bf7d8562abd5b880909d51c5e5d25416e6557680aee5"
        )

    def test_v_as_y_parity_round_trips(self):
        # The node accepts v = 0/1 as well as 27/28; decoding keeps the bytes.
        fields = _fields(DECODE_MINIMAL)
        sig = bytearray(fields[-1])
        sig[64] -= 27
        fields[-1] = bytes(sig)
        raw = _raw(fields)
        tx = TempoTransaction.decode(raw)
        assert tx.sender_signature.v in (0, 1)
        assert bytes(tx.sender_address).hex() == (
            "0e6fd5d3582d21c6abf24d21987e11d8ceeb6098"
        )
        assert tx.encode() == raw
        assert tx.hash() == keccak(raw)


class TestDecodeRoundTrip:
    def test_secp256k1_all_fields(self):
        tx = _base_tx(
            nonce=7,
            nonce_key=2**200,
            valid_before=2_000_000_000,
            valid_after=1_000_000_000,
            fee_token=PATH_USD,
            calls=(
                Call.create(to="0x" + "ab" * 20, value=10**30, data=b"\x01\x02"),
                Call.create(to=PATH_USD, data=TRANSFER),
            ),
            access_list=(
                AccessListItem.create(
                    address="0x" + "cd" * 20, storage_keys=(b"\x01" * 32, b"\x02" * 32)
                ),
            ),
        ).sign(SENDER_KEY)
        decoded = TempoTransaction.decode(tx.encode())
        assert decoded == tx
        assert decoded.recover_sender() == _addr(SENDER_KEY)

    def test_contract_creation(self):
        tx = _base_tx(calls=(Call.create(to=b"", data=b"\x60\x00"),)).sign(SENDER_KEY)
        decoded = TempoTransaction.decode(tx.encode())
        assert bytes(decoded.calls[0].to) == b""
        assert decoded == tx

    def test_sponsored(self):
        tx = (
            _base_tx(fee_token=PATH_USD, awaiting_fee_payer=True)
            .sign(SENDER_KEY)
            .sign(FEE_PAYER_KEY, for_fee_payer=True)
        )
        decoded = TempoTransaction.decode(tx.encode())
        assert decoded.recover_sender() == _addr(SENDER_KEY)
        assert decoded.recover_fee_payer() == _addr(FEE_PAYER_KEY)
        assert decoded.fee_token == tx.fee_token
        assert decoded.hash() == tx.hash()

    def test_sponsored_awaiting_fee_payer(self):
        # What a fee payer server receives: signed by the sender, with the 0x00
        # marker in place of the fee payer signature and no fee token yet.
        tx = _base_tx(awaiting_fee_payer=True).sign(SENDER_KEY)
        raw = tx.encode()
        decoded = TempoTransaction.decode(raw)
        assert decoded.awaiting_fee_payer
        assert decoded.fee_payer_signature is None
        assert decoded.recover_sender() == _addr(SENDER_KEY)
        assert decoded.recover_fee_payer() is None
        assert decoded.encode() == raw
        cosigned = decoded.sign(FEE_PAYER_KEY, for_fee_payer=True)
        redecoded = TempoTransaction.decode(cosigned.encode())
        assert redecoded.recover_sender() == _addr(SENDER_KEY)
        assert redecoded.recover_fee_payer() == _addr(FEE_PAYER_KEY)

    def test_keychain_v2_with_periodic_key_authorization(self):
        auth = KeyAuthorization(
            key_id=_addr(ACCESS_KEY),
            chain_id=1337,
            expiry=4102444800,
            limits=[TokenLimit(token=PATH_USD, limit=5_000_000, period=86400)],
        ).sign(ROOT_KEY)
        tx = _base_tx(key_authorization=auth).sign_access_key(
            ACCESS_KEY, _addr(ROOT_KEY)
        )
        decoded = TempoTransaction.decode(tx.encode())
        assert decoded == tx
        assert decoded.key_authorization.authorization.limits[0].period == 86400
        assert decoded.recover_sender() == _addr(ROOT_KEY)
        msg_hash = attrs.evolve(decoded, sender_signature=None).get_signing_hash()
        assert decoded.sender_signature.recover_key_id(msg_hash) == _addr(ACCESS_KEY)

    def test_keychain_v1(self):
        tx = _base_tx()
        msg_hash = tx.get_signing_hash()
        signed = Account.from_key(ACCESS_KEY).unsafe_sign_hash(msg_hash)
        sig = KeychainSignature(
            root_account=_addr(ROOT_KEY),
            inner=Signature(r=signed.r, s=signed.s, v=signed.v),
            version=1,
        )
        assert sig.to_bytes()[0] == 0x03
        assert KeychainSignature.from_bytes(sig.to_bytes()) == sig
        raw = attrs.evolve(tx, sender_signature=sig).encode()
        decoded = TempoTransaction.decode(raw)
        assert decoded.sender_signature == sig
        assert bytes(decoded.sender_address) == bytes.fromhex(_addr(ROOT_KEY)[2:])
        assert sig.recover_key_id(msg_hash) == _addr(ACCESS_KEY)


class TestDecodeRejects:
    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(b"", id="empty"),
            pytest.param(b"\x76", id="type-byte-only"),
            pytest.param(b"\x77" + DECODE_MINIMAL[1:], id="wrong-type"),
            pytest.param(DECODE_MINIMAL[:-1], id="truncated"),
            pytest.param(DECODE_MINIMAL + b"\x00", id="trailing-byte"),
            pytest.param(TEMPO_TS_FEE_PAYER_TRAILER, id="tempo-ts-fee-payer-trailer"),
        ],
    )
    def test_malformed_envelope(self, raw):
        with pytest.raises(ValueError):
            TempoTransaction.decode(raw)

    def test_high_s(self):
        fields = _fields(DECODE_MINIMAL)
        sig = fields[-1]
        s = int.from_bytes(sig[32:64], "big")
        v = 28 if sig[64] == 27 else 27
        fields[-1] = sig[:32] + (SECP256K1_N - s).to_bytes(32, "big") + bytes([v])
        with pytest.raises(ValueError, match="low-s"):
            TempoTransaction.decode(_raw(fields))

    @pytest.mark.parametrize("v", [2, 26, 29, 35, 37])
    def test_bad_v(self, v):
        fields = _fields(DECODE_MINIMAL)
        fields[-1] = fields[-1][:64] + bytes([v])
        with pytest.raises(ValueError, match="signature v"):
            TempoTransaction.decode(_raw(fields))

    @pytest.mark.parametrize(
        ("index", "value"),
        [
            pytest.param(0, b"\x00\x05\x39", id="chain-id-leading-zero"),
            pytest.param(
                3, b"\x00" + (2_000_000).to_bytes(3, "big"), id="gas-leading-zero"
            ),
            pytest.param(7, b"\x00", id="nonce-zero-byte"),
            pytest.param(3, b"\x01" * 9, id="gas-overflows-u64"),
            pytest.param(1, b"\x01" * 17, id="priority-fee-overflows-u128"),
            pytest.param(10, b"\x01" * 19, id="fee-token-wrong-length"),
            pytest.param(4, [], id="no-calls"),
            pytest.param(4, b"", id="calls-not-a-list"),
        ],
    )
    def test_bad_field(self, index, value):
        fields = _fields(DECODE_MINIMAL)
        fields[index] = value
        with pytest.raises(ValueError):
            TempoTransaction.decode(_raw(fields))

    def test_non_canonical_length_prefix(self):
        fields = _fields(DECODE_MINIMAL)
        # chain_id 1337 re-encoded with a long-form string prefix.
        payload = b"".join(rlp.encode(f) for f in fields)
        bad_chain = b"\xb8\x02\x05\x39"
        payload = bad_chain + payload[len(rlp.encode(fields[0])) :]
        raw = b"\x76" + b"\xf9" + len(payload).to_bytes(2, "big") + payload
        with pytest.raises(ValueError, match="RLP"):
            TempoTransaction.decode(raw)

    def test_equal_validity_window(self):
        tx = _base_tx(valid_after=1000, valid_before=2000).sign(SENDER_KEY)
        fields = _fields(tx.encode())
        fields[9] = fields[8]  # valid_after = valid_before
        with pytest.raises(ValueError, match="valid_after"):
            TempoTransaction.decode(_raw(fields))

    def test_create_not_first(self):
        tx = _base_tx(
            calls=(
                Call.create(to=PATH_USD, data=TRANSFER),
                Call.create(to=b"", data=b"\x60\x00"),
            )
        ).sign(SENDER_KEY)
        with pytest.raises(ValueError, match="CREATE"):
            TempoTransaction.decode(tx.encode())

    def test_fee_payer_high_s(self):
        tx = (
            _base_tx(awaiting_fee_payer=True)
            .sign(SENDER_KEY)
            .sign(FEE_PAYER_KEY, for_fee_payer=True)
        )
        fields = _fields(tx.encode())
        v, r, s = fields[11]
        s_int = int.from_bytes(s, "big")
        flipped = b"" if v == b"\x01" else b"\x01"
        fields[11] = [flipped, r, (SECP256K1_N - s_int).to_bytes(32, "big")]
        with pytest.raises(ValueError, match="low-s"):
            TempoTransaction.decode(_raw(fields))

    def test_fee_payer_v_out_of_range(self):
        tx = (
            _base_tx(awaiting_fee_payer=True)
            .sign(SENDER_KEY)
            .sign(FEE_PAYER_KEY, for_fee_payer=True)
        )
        fields = _fields(tx.encode())
        fields[11] = [27, fields[11][1], fields[11][2]]
        with pytest.raises(ValueError, match="fee_payer_signature.v"):
            TempoTransaction.decode(_raw(fields))

    def test_non_canonical_key_authorization(self):
        # An explicit zero token-limit period is non-canonical.
        fields = _fields(DECODE_KA_EXPIRY_PERIODIC_LIMIT)
        fields[13][0][4][0][2] = b""
        with pytest.raises(ValueError):
            TempoTransaction.decode(_raw(fields))

    def test_unknown_signature_type(self):
        fields = _fields(DECODE_MINIMAL)
        fields[-1] = b"\x09" + b"\x00" * 70
        with pytest.raises(ValueError, match="unknown signature type"):
            TempoTransaction.decode(_raw(fields))

    def test_nested_keychain(self):
        fields = _fields(DECODE_MINIMAL)
        inner = b"\x04" + b"\x11" * 20 + fields[-1]
        fields[-1] = b"\x04" + b"\x22" * 20 + inner
        with pytest.raises(ValueError, match="another keychain"):
            TempoTransaction.decode(_raw(fields))

    def test_malformed_p256_length(self):
        fields = _fields(DECODE_MINIMAL)
        fields[-1] = b"\x01" + b"\x00" * 128
        with pytest.raises(ValueError, match="P256 signature length"):
            TempoTransaction.decode(_raw(fields))


class TestDecodeUnsupported:
    @pytest.mark.parametrize(
        ("signature", "kind"),
        [
            pytest.param(b"\x01" + b"\x11" * 129, "P256", id="p256"),
            pytest.param(b"\x02" + b"\x11" * 200, "WebAuthn", id="webauthn"),
            pytest.param(
                b"\x04" + b"\x22" * 20 + b"\x01" + b"\x11" * 129,
                "P256",
                id="keychain-p256",
            ),
        ],
    )
    def test_p256_and_webauthn_senders(self, signature, kind):
        fields = _fields(DECODE_MINIMAL)
        fields[-1] = signature
        with pytest.raises(NotImplementedError, match=kind):
            TempoTransaction.decode(_raw(fields))

    def test_non_empty_tempo_authorization_list(self):
        fields = _fields(DECODE_MINIMAL)
        fields[12] = [[1337, b"\x11" * 20, 0, b"\x22" * 65]]
        with pytest.raises(NotImplementedError, match="tempo_authorization_list"):
            TempoTransaction.decode(_raw(fields))


class TestTokenLimitFromRlp:
    @pytest.mark.parametrize(
        "item",
        [
            pytest.param([b"\x20" * 20, [b"\x01"]], id="limit-is-list"),
            pytest.param([[b"\x20"], b"\x01"], id="token-is-list"),
            pytest.param([b"\x20" * 20, b"\x01", [b"\x01"]], id="period-is-list"),
        ],
    )
    def test_malformed_fields_raise_value_error(self, item):
        with pytest.raises(ValueError):
            TokenLimit.from_rlp(item)


class TestRecovery:
    def test_recover_sender_requires_signature(self):
        with pytest.raises(ValueError, match="no sender signature"):
            _base_tx().recover_sender()

    def test_signature_recover(self):
        msg_hash = keccak(b"hello")
        signed = Account.from_key(SENDER_KEY).unsafe_sign_hash(msg_hash)
        for v in (signed.v, signed.v - 27):
            sig = Signature(r=signed.r, s=signed.s, v=v)
            assert sig.recover(msg_hash) == _addr(SENDER_KEY)
