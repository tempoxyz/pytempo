"""Tests for the strongly-typed models."""

import pytest

from pytempo import (
    AccessListItem,
    Call,
    Signature,
    TempoTransaction,
    as_address,
    as_bytes,
    as_hash32,
)


class TestTypes:
    """Test type coercion helpers."""

    def test_as_address_from_hex(self):
        addr = as_address("0xF0109fC8DF283027b6285cc889F5aA624EaC1F55")
        assert len(addr) == 20
        assert isinstance(addr, bytes)

    def test_as_address_from_bytes(self):
        raw = bytes.fromhex("F0109fC8DF283027b6285cc889F5aA624EaC1F55")
        addr = as_address(raw)
        assert len(addr) == 20

    def test_as_address_empty(self):
        addr = as_address("")
        assert addr == b""

    def test_as_address_invalid_length(self):
        with pytest.raises(ValueError, match="20 bytes"):
            as_address("0x1234")

    def test_as_hash32_from_hex(self):
        h = as_hash32("0x" + "ab" * 32)
        assert len(h) == 32

    def test_as_hash32_invalid_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            as_hash32("0x1234")

    def test_as_bytes_from_hex(self):
        b = as_bytes("0xabcdef")
        assert b == bytes.fromhex("abcdef")

    def test_as_bytes_empty(self):
        assert as_bytes("0x") == b""
        assert as_bytes("") == b""

    def test_as_bytes_rejects_int(self):
        with pytest.raises(TypeError, match="expected str, bytes"):
            as_bytes(20)

    def test_as_address_rejects_int(self):
        with pytest.raises(TypeError, match="expected str, bytes"):
            as_address(20)

    def test_as_hash32_rejects_int(self):
        with pytest.raises(TypeError, match="expected str, bytes"):
            as_hash32(32)


class TestCall:
    """Test Call dataclass."""

    def test_create_call(self):
        call = Call.create(
            to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
            value=1000,
            data="0xabcd",
        )
        assert len(call.to) == 20
        assert call.value == 1000
        assert call.data == bytes.fromhex("abcd")

    def test_call_validate_negative_value(self):
        with pytest.raises(ValueError, match="value must be >= 0"):
            Call(to=as_address("0x" + "a" * 40), value=-1, data=b"")

    def test_call_as_rlp_list(self):
        call = Call.create(to="0x" + "a" * 40, value=100, data="0x1234")
        rlp_list = call.as_rlp_list()
        assert len(rlp_list) == 3
        assert rlp_list[1] == 100


class TestAccessListItem:
    """Test AccessListItem dataclass."""

    def test_create_access_list_item(self):
        item = AccessListItem.create(
            address="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
            storage_keys=("0x" + "ab" * 32,),
        )
        assert len(item.address) == 20
        assert len(item.storage_keys) == 1
        assert len(item.storage_keys[0]) == 32


class TestSignature:
    """Test Signature dataclass."""

    def test_signature_to_bytes(self):
        sig = Signature(r=1, s=2, v=27)
        sig_bytes = sig.to_bytes()
        assert len(sig_bytes) == 65
        assert sig_bytes[64] == 27

    def test_signature_from_bytes(self):
        r = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        s = 0x1234567890ABCDEF1234567890ABCDEF  # Low-s value (under half of secp256k1 n)
        v = 27
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
        sig = Signature.from_bytes(raw)
        assert sig.r == r
        assert sig.s == s
        assert sig.v == v

    def test_signature_from_bytes_invalid_length(self):
        with pytest.raises(ValueError, match="65 bytes"):
            Signature.from_bytes(b"\x00" * 64)

    def test_signature_rejects_zero_r(self):
        with pytest.raises(ValueError, match="signature r must be in range"):
            Signature(r=0, s=1, v=27)

    def test_signature_rejects_zero_s(self):
        with pytest.raises(ValueError, match="signature s must be in range"):
            Signature(r=1, s=0, v=27)

    def test_signature_rejects_high_s(self):
        from pytempo.models import SECP256K1_HALF_N

        with pytest.raises(ValueError, match="low-s"):
            Signature(r=1, s=SECP256K1_HALF_N + 1, v=27)

    def test_signature_rejects_invalid_v(self):
        with pytest.raises(ValueError, match="v must be"):
            Signature(r=1, s=1, v=99)


class TestTempoTransaction:
    """Test the immutable TempoTransaction."""

    def test_validate_empty_calls(self):
        tx = TempoTransaction(chain_id=1, gas_limit=21000, calls=())
        with pytest.raises(ValueError, match="at least one call"):
            tx.validate()

    def test_validate_invalid_chain_id(self):
        tx = TempoTransaction(
            chain_id=0,
            gas_limit=21000,
            calls=(Call.create(to="0x" + "a" * 40, value=0, data=b""),),
        )
        with pytest.raises(ValueError, match="chain_id must be > 0"):
            tx.validate()

    def test_validate_fee_mismatch(self):
        tx = TempoTransaction(
            chain_id=1,
            gas_limit=21000,
            max_fee_per_gas=100,
            max_priority_fee_per_gas=200,
            calls=(Call.create(to="0x" + "a" * 40, value=0, data=b""),),
        )
        with pytest.raises(ValueError, match="cannot exceed"):
            tx.validate()

    def test_sign_returns_new_transaction(self):
        tx = TempoTransaction(
            chain_id=42429,
            gas_limit=100000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=1000000000,
            calls=(
                Call.create(
                    to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=0, data=b""
                ),
            ),
        )
        private_key = (
            "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"
        )

        signed_tx = tx.sign(private_key)

        assert signed_tx is not tx
        assert signed_tx.sender_signature is not None
        assert signed_tx.sender_address is not None
        assert tx.sender_signature is None

    def test_create_factory(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=1000000000,
        )

        assert tx.chain_id == 42429
        assert tx.gas_limit == 100000
        assert tx.calls == ()

    def test_create_with_fee_token_coercion(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            fee_token="0x20c0000000000000000000000000000000000001",
        )

        assert tx.fee_token is not None
        assert len(tx.fee_token) == 20

    def test_create_with_calls(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            max_fee_per_gas=2000000000,
            max_priority_fee_per_gas=1000000000,
            calls=(
                Call.create(
                    to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=1000
                ),
            ),
        )

        assert tx.chain_id == 42429
        assert tx.gas_limit == 100000
        assert len(tx.calls) == 1
        assert tx.calls[0].value == 1000

    def test_create_multiple_calls(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=200000,
            calls=(
                Call.create(to="0x" + "a" * 40, value=100),
                Call.create(to="0x" + "b" * 40, value=200, data="0xabcd"),
            ),
        )

        assert len(tx.calls) == 2
        assert tx.calls[0].value == 100
        assert tx.calls[1].value == 200

    def test_create_with_access_list(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            calls=(Call.create(to="0x" + "a" * 40),),
            access_list=(
                AccessListItem.create(
                    address="0x" + "b" * 40,
                    storage_keys=("0x" + "c" * 64,),
                ),
            ),
        )

        assert len(tx.access_list) == 1
        assert len(tx.access_list[0].storage_keys) == 1

    def test_create_sponsored(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            calls=(Call.create(to="0x" + "a" * 40),),
            awaiting_fee_payer=True,
        )

        assert tx.awaiting_fee_payer is True

    def test_create_with_fee_token(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            fee_token="0x20c0000000000000000000000000000000000001",
            calls=(Call.create(to="0x" + "a" * 40),),
        )

        assert tx.fee_token is not None
        assert len(tx.fee_token) == 20

    def test_create_validity_window(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=100000,
            valid_after=1000,
            valid_before=2000,
            calls=(Call.create(to="0x" + "a" * 40),),
        )

        assert tx.valid_after == 1000
        assert tx.valid_before == 2000

    def test_contract_creation(self):
        tx = TempoTransaction.create(
            chain_id=42429,
            gas_limit=500000,
            calls=(Call.create(to=b"", value=0, data="0x6080604052"),),
        )

        assert len(tx.calls) == 1
        assert tx.calls[0].to == b""

    def test_from_dict_camel_case(self):
        tx = TempoTransaction.from_dict(
            {
                "chainId": 42429,
                "gas": 100000,
                "maxFeePerGas": 2000000000,
                "to": "0x" + "a" * 40,
                "value": 1000,
            }
        )

        assert tx.chain_id == 42429
        assert tx.gas_limit == 100000
        assert len(tx.calls) == 1
        assert tx.calls[0].value == 1000

    def test_from_dict_snake_case(self):
        tx = TempoTransaction.from_dict(
            {
                "chain_id": 42429,
                "gas_limit": 100000,
                "max_fee_per_gas": 2000000000,
                "calls": [{"to": "0x" + "a" * 40, "value": 500}],
            }
        )

        assert tx.chain_id == 42429
        assert tx.gas_limit == 100000
        assert len(tx.calls) == 1
        assert tx.calls[0].value == 500

    def test_immutability_preserved(self):
        import attrs

        tx1 = TempoTransaction.create(
            chain_id=42429,
            calls=(Call.create(to="0x" + "a" * 40),),
        )
        tx2 = attrs.evolve(tx1, gas_limit=200000)

        assert tx1.gas_limit == 21000
        assert tx2.gas_limit == 200000
        assert tx1 is not tx2
