"""Tests for the T12 TIP-1006 ``burnAt`` binding."""

from unittest.mock import MagicMock

from eth_utils import function_signature_to_4byte_selector, keccak
from web3 import Web3

from pytempo.contracts import ALPHA_USD, TIP20, TIP20_ABI

RECIPIENT = "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"


def test_burn_at_encodes_call():
    call = TIP20(ALPHA_USD).burn_at(sender=RECIPIENT, amount=5)

    assert call.to == bytes.fromhex(ALPHA_USD[2:])
    assert call.data == function_signature_to_4byte_selector(
        "burnAt(address,uint256)"
    ) + Web3().codec.encode(["address", "uint256"], [RECIPIENT, 5])


def test_burn_at_role_queries_constant():
    role = keccak(text="BURN_AT_ROLE")
    w3 = MagicMock()
    w3.eth.call.return_value = role

    assert TIP20(ALPHA_USD).burn_at_role(w3) == role

    tx = w3.eth.call.call_args.args[0]
    assert tx["to"] == ALPHA_USD
    assert (
        tx["data"]
        == "0x" + function_signature_to_4byte_selector("BURN_AT_ROLE()").hex()
    )


def test_burn_at_event_abi_layout():
    entries = [
        entry
        for entry in TIP20_ABI
        if entry.get("type") == "event" and entry.get("name") == "BurnAt"
    ]

    assert len(entries) == 1
    assert [
        (arg["name"], arg["type"], arg["indexed"]) for arg in entries[0]["inputs"]
    ] == [
        ("burner", "address", True),
        ("from", "address", True),
        ("amount", "uint256", True),
    ]
