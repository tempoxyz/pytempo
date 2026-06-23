"""Tests for T6 contract bindings: TIP-403 receive policies, ReceivePolicyGuard,
SignatureVerifier."""

from unittest.mock import MagicMock

import pytest
from eth_utils import function_signature_to_4byte_selector

from pytempo.contracts import (
    RECEIVE_POLICY_GUARD_ADDRESS,
    SIGNATURE_VERIFIER_ADDRESS,
    TIP403_REGISTRY_ADDRESS,
    BlockedReason,
    PolicyType,
    ReceivePolicyGuard,
    SignatureVerifier,
    TIP403Registry,
)

RECOVERY = "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
ADDR = "0x" + "aa" * 20


def _selector(signature: str) -> bytes:
    return function_signature_to_4byte_selector(signature)


class TestTIP403ReceivePolicy:
    def test_set_receive_policy_selector(self):
        call = TIP403Registry.set_receive_policy(
            sender_policy_id=0, token_filter_id=7, recovery_authority=RECOVERY
        )
        assert bytes(call.to) == bytes.fromhex("403c" + "00" * 18)
        assert call.data[:4] == _selector("setReceivePolicy(uint64,uint64,address)")

    def test_receive_policy_decodes(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (
            (1).to_bytes(32, "big")  # hasReceivePolicy
            + (5).to_bytes(32, "big")  # senderPolicyId
            + (1).to_bytes(32, "big")  # senderPolicyType = BLACKLIST
            + (7).to_bytes(32, "big")  # tokenFilterId
            + (0).to_bytes(32, "big")  # tokenFilterType = WHITELIST
            + (b"\x00" * 12 + bytes.fromhex("bb" * 20))  # recoveryAuthority
        )
        res = TIP403Registry.receive_policy(mock_w3, account=ADDR)
        assert res["has_receive_policy"] is True
        assert res["sender_policy_id"] == 5
        assert res["sender_policy_type"] is PolicyType.BLACKLIST
        assert res["token_filter_id"] == 7
        assert res["token_filter_type"] is PolicyType.WHITELIST
        assert res["recovery_authority"].lower() == ("0x" + "bb" * 20).lower()

    def test_receive_policy_rejects_wrong_length(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 64
        with pytest.raises(ValueError, match="wrong length"):
            TIP403Registry.receive_policy(mock_w3, account=ADDR)

    def test_validate_receive_policy_decodes(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big") + (2).to_bytes(
            32, "big"
        )
        res = TIP403Registry.validate_receive_policy(
            mock_w3, token=ADDR, sender=ADDR, receiver=ADDR
        )
        assert res["authorized"] is False
        assert res["blocked_reason"] is BlockedReason.RECEIVE_POLICY

    def test_validate_receive_policy_selector(self):
        # exercise the encode path with a real offline encode
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (1).to_bytes(32, "big") + (0).to_bytes(
            32, "big"
        )
        res = TIP403Registry.validate_receive_policy(
            mock_w3, token=ADDR, sender=ADDR, receiver=ADDR
        )
        assert res["authorized"] is True
        assert res["blocked_reason"] is BlockedReason.NONE
        sent = mock_w3.eth.call.call_args[0][0]
        assert bytes.fromhex(sent["data"][2:10]) == _selector(
            "validateReceivePolicy(address,address,address)"
        )

    def test_receive_policy_requires_account(self):
        with pytest.raises(ValueError, match="account"):
            TIP403Registry.receive_policy(MagicMock(), account="")


class TestReceivePolicyGuard:
    def test_balance_of(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (1234).to_bytes(32, "big")
        amount = ReceivePolicyGuard.balance_of(mock_w3, receipt=b"\x01\x02\x03")
        assert amount == 1234
        sent = mock_w3.eth.call.call_args[0][0]
        assert bytes.fromhex(sent["data"][2:10]) == _selector("balanceOf(bytes)")

    def test_claim_call(self):
        call = ReceivePolicyGuard.claim(to=RECOVERY, receipt=b"\xaa")
        assert bytes(call.to) == bytes.fromhex("b10c" + "00" * 18)
        assert call.data[:4] == _selector("claim(address,bytes)")

    def test_claim_requires_to(self):
        with pytest.raises(ValueError, match="to required"):
            ReceivePolicyGuard.claim(to="", receipt=b"\xaa")

    def test_burn_blocked_receipt_call(self):
        call = ReceivePolicyGuard.burn_blocked_receipt(receipt=b"\xbb")
        assert call.data[:4] == _selector("burnBlockedReceipt(bytes)")


class TestSignatureVerifier:
    def test_recover(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 12 + bytes.fromhex("cc" * 20)
        signer = SignatureVerifier.recover(
            mock_w3, hash="0x" + "11" * 32, signature=b"\x00" * 65
        )
        assert signer.lower() == ("0x" + "cc" * 20).lower()
        sent = mock_w3.eth.call.call_args[0][0]
        assert bytes.fromhex(sent["data"][2:10]) == _selector("recover(bytes32,bytes)")

    def test_verify(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (1).to_bytes(32, "big")
        ok = SignatureVerifier.verify(
            mock_w3, signer=ADDR, hash="0x" + "11" * 32, signature=b"\x00" * 65
        )
        assert ok is True
        sent = mock_w3.eth.call.call_args[0][0]
        assert bytes.fromhex(sent["data"][2:10]) == _selector(
            "verify(address,bytes32,bytes)"
        )

    def test_verify_requires_signer(self):
        with pytest.raises(ValueError, match="signer"):
            SignatureVerifier.verify(
                MagicMock(), signer="", hash="0x" + "11" * 32, signature=b"\x00" * 65
            )


def test_addresses():
    assert TIP403_REGISTRY_ADDRESS.lower().startswith("0x403c")
    assert RECEIVE_POLICY_GUARD_ADDRESS == "0xB10C000000000000000000000000000000000000"
    assert SIGNATURE_VERIFIER_ADDRESS == "0x5165300000000000000000000000000000000000"


class TestWrongLengthResponses:
    def test_validate_receive_policy_wrong_length(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 32
        with pytest.raises(ValueError, match="wrong length"):
            TIP403Registry.validate_receive_policy(
                mock_w3, token=ADDR, sender=ADDR, receiver=ADDR
            )

    def test_balance_of_wrong_length(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 16
        with pytest.raises(ValueError, match="wrong length"):
            ReceivePolicyGuard.balance_of(mock_w3, receipt=b"\x01")

    def test_recover_wrong_length(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 20
        with pytest.raises(ValueError, match="wrong length"):
            SignatureVerifier.recover(
                mock_w3, hash="0x" + "11" * 32, signature=b"\x00" * 65
            )

    def test_verify_wrong_length(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 64
        with pytest.raises(ValueError, match="wrong length"):
            SignatureVerifier.verify(
                mock_w3, signer=ADDR, hash="0x" + "11" * 32, signature=b"\x00" * 65
            )


class TestEnumOutOfRange:
    def test_receive_policy_bad_policy_type(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (
            (1).to_bytes(32, "big")  # hasReceivePolicy
            + (5).to_bytes(32, "big")  # senderPolicyId
            + (9).to_bytes(32, "big")  # senderPolicyType = invalid
            + (7).to_bytes(32, "big")  # tokenFilterId
            + (0).to_bytes(32, "big")  # tokenFilterType
            + (b"\x00" * 12 + bytes.fromhex("bb" * 20))  # recoveryAuthority
        )
        with pytest.raises(ValueError, match="PolicyType"):
            TIP403Registry.receive_policy(mock_w3, account=ADDR)

    def test_validate_receive_policy_bad_blocked_reason(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big") + (9).to_bytes(
            32, "big"
        )
        with pytest.raises(ValueError, match="BlockedReason"):
            TIP403Registry.validate_receive_policy(
                mock_w3, token=ADDR, sender=ADDR, receiver=ADDR
            )


class TestReadCallTargets:
    def test_receive_policy_targets_registry(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (
            (1).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (b"\x00" * 32)
        )
        TIP403Registry.receive_policy(mock_w3, account=ADDR)
        assert mock_w3.eth.call.call_args[0][0]["to"] == TIP403_REGISTRY_ADDRESS

    def test_balance_of_targets_guard(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big")
        ReceivePolicyGuard.balance_of(mock_w3, receipt=b"\x01")
        assert mock_w3.eth.call.call_args[0][0]["to"] == RECEIVE_POLICY_GUARD_ADDRESS

    def test_recover_targets_verifier(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 12 + bytes.fromhex("cc" * 20)
        SignatureVerifier.recover(
            mock_w3, hash="0x" + "11" * 32, signature=b"\x00" * 65
        )
        assert mock_w3.eth.call.call_args[0][0]["to"] == SIGNATURE_VERIFIER_ADDRESS


class TestAbiOutputLayout:
    """Guard against upstream ABI *output* drift.

    ``tip403.py`` decodes ``receivePolicy`` / ``validateReceivePolicy`` outputs
    by manual word-slicing, so the vendored ABI's output definitions are never
    exercised by the call builders. These tests assert the (name, type) output
    layout so a tempo-std change to either signature fails loudly here.
    """

    @staticmethod
    def _outputs(abi: list, name: str) -> list:
        entries = [e for e in abi if e.get("name") == name]
        assert len(entries) == 1, f"expected exactly one {name} entry"
        return [(o.get("name"), o["type"]) for o in entries[0]["outputs"]]

    def test_receive_policy_output_layout(self):
        from pytempo.contracts.abis import TIP403_REGISTRY_ABI

        assert self._outputs(TIP403_REGISTRY_ABI, "receivePolicy") == [
            ("hasReceivePolicy", "bool"),
            ("senderPolicyId", "uint64"),
            ("senderPolicyType", "uint8"),
            ("tokenFilterId", "uint64"),
            ("tokenFilterType", "uint8"),
            ("recoveryAuthority", "address"),
        ]

    def test_validate_receive_policy_output_layout(self):
        from pytempo.contracts.abis import TIP403_REGISTRY_ABI

        assert self._outputs(TIP403_REGISTRY_ABI, "validateReceivePolicy") == [
            ("authorized", "bool"),
            ("blockedReason", "uint8"),
        ]


def test_bindings_import_smoke():
    from pytempo.contracts import (
        InboundKind,
        ReceivePolicyGuard,
        SignatureVerifier,
        TIP403Registry,
    )

    assert TIP403Registry.ADDRESS == TIP403_REGISTRY_ADDRESS
    assert ReceivePolicyGuard.ADDRESS == RECEIVE_POLICY_GUARD_ADDRESS
    assert SignatureVerifier.ADDRESS == SIGNATURE_VERIFIER_ADDRESS
    assert InboundKind.TRANSFER == 0
    assert InboundKind.MINT == 1
