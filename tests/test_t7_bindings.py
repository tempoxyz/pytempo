"""Tests for T7 contract bindings: StorageCredits precompile (TIP-1060)."""

from unittest.mock import MagicMock

import pytest
from eth_utils import function_signature_to_4byte_selector

from pytempo.contracts import (
    STORAGE_CREDITS_ADDRESS,
    StorageCreditMode,
    StorageCredits,
)

ADDR = "0x" + "aa" * 20


def _selector(signature: str) -> bytes:
    return function_signature_to_4byte_selector(signature)


class TestStorageCreditsAddress:
    def test_address(self):
        assert StorageCredits.ADDRESS == STORAGE_CREDITS_ADDRESS
        assert bytes(bytes.fromhex(STORAGE_CREDITS_ADDRESS[2:])) == bytes.fromhex(
            "1060" + "00" * 18
        )


class TestSetMode:
    def test_selector(self):
        call = StorageCredits.set_mode(StorageCreditMode.PRESERVE)
        assert bytes(call.to) == bytes.fromhex("1060" + "00" * 18)
        assert call.data[:4] == _selector("setMode(uint8)")

    def test_encodes_each_mode(self):
        for mode in (
            StorageCreditMode.REFUND,
            StorageCreditMode.PRESERVE,
            StorageCreditMode.DIRECT,
        ):
            call = StorageCredits.set_mode(mode)
            # last byte of the single ABI word is the mode value
            assert call.data[-1] == int(mode)

    def test_accepts_int(self):
        call = StorageCredits.set_mode(2)
        assert call.data[:4] == _selector("setMode(uint8)")
        assert call.data[-1] == 2

    def test_rejects_reserved_mode(self):
        with pytest.raises(ValueError):
            StorageCredits.set_mode(3)

    def test_rejects_negative_mode(self):
        with pytest.raises(ValueError):
            StorageCredits.set_mode(-1)


class TestSetBudget:
    def test_selector(self):
        call = StorageCredits.set_budget(5)
        assert bytes(call.to) == bytes.fromhex("1060" + "00" * 18)
        assert call.data[:4] == _selector("setBudget(uint64)")
        assert call.data[-1] == 5

    def test_zero_budget_allowed(self):
        call = StorageCredits.set_budget(0)
        assert call.data[:4] == _selector("setBudget(uint64)")

    def test_max_uint64_allowed(self):
        call = StorageCredits.set_budget(2**64 - 1)
        assert call.data[:4] == _selector("setBudget(uint64)")

    def test_rejects_overflow(self):
        with pytest.raises(ValueError, match="uint64"):
            StorageCredits.set_budget(2**64)

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="uint64"):
            StorageCredits.set_budget(-1)


class TestBalanceOf:
    def test_decodes(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (42).to_bytes(32, "big")
        assert StorageCredits.balance_of(mock_w3, account=ADDR) == 42

    def test_encodes_selector(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big")
        StorageCredits.balance_of(mock_w3, account=ADDR)
        sent = mock_w3.eth.call.call_args[0][0]
        assert sent["to"] == STORAGE_CREDITS_ADDRESS
        assert bytes.fromhex(sent["data"][2:10]) == _selector("balanceOf(address)")

    def test_rejects_empty_account(self):
        with pytest.raises(ValueError, match="account required"):
            StorageCredits.balance_of(MagicMock(), account="")

    def test_rejects_overflow(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (2**64).to_bytes(32, "big")
        with pytest.raises(ValueError, match="uint64"):
            StorageCredits.balance_of(mock_w3, account=ADDR)


class TestModeOf:
    def test_decodes(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (2).to_bytes(32, "big")
        assert StorageCredits.mode_of(mock_w3, account=ADDR) is StorageCreditMode.DIRECT

    def test_default_refund(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big")
        assert StorageCredits.mode_of(mock_w3, account=ADDR) is StorageCreditMode.REFUND

    def test_rejects_unknown_mode(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (3).to_bytes(32, "big")
        with pytest.raises(ValueError, match="unknown mode"):
            StorageCredits.mode_of(mock_w3, account=ADDR)

    def test_rejects_empty_account(self):
        with pytest.raises(ValueError, match="account required"):
            StorageCredits.mode_of(MagicMock(), account="")


class TestBudgetOf:
    def test_decodes(self):
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (7).to_bytes(32, "big")
        assert StorageCredits.budget_of(mock_w3, account=ADDR) == 7

    def test_rejects_empty_account(self):
        with pytest.raises(ValueError, match="account required"):
            StorageCredits.budget_of(MagicMock(), account="")
