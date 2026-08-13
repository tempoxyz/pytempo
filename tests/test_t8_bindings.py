"""Tests for the T8 CurrentCommittee binding."""

from unittest.mock import MagicMock

import pytest
from eth_abi.exceptions import DecodingError
from eth_utils import function_signature_to_4byte_selector
from web3 import Web3

from pytempo.contracts import (
    CURRENT_COMMITTEE_ABI,
    CURRENT_COMMITTEE_ADDRESS,
    CurrentCommittee,
)


def _mock_w3(result: bytes):
    w3 = MagicMock()
    w3.codec = Web3().codec
    w3.eth.call.return_value = result
    return w3


def test_current_committee_exports():
    assert CurrentCommittee.ADDRESS == CURRENT_COMMITTEE_ADDRESS
    assert CURRENT_COMMITTEE_ADDRESS.lower() == (
        "0xc077e00000000000000000000000000000000000"
    )


def test_get_committee_members_abi_output_layout():
    entries = [
        entry
        for entry in CURRENT_COMMITTEE_ABI
        if entry.get("name") == "getCommitteeMembers"
    ]

    assert len(entries) == 1
    assert [(output["name"], output["type"]) for output in entries[0]["outputs"]] == [
        ("epoch", "uint64"),
        ("publicKeys", "bytes32[]"),
    ]


def test_get_committee_members_encodes_call_and_decodes_result():
    codec = Web3().codec
    expected_keys = (bytes.fromhex("11" * 32), bytes.fromhex("22" * 32))
    w3 = _mock_w3(codec.encode(["uint64", "bytes32[]"], [42, expected_keys]))

    assert CurrentCommittee.get_committee_members(w3) == (42, expected_keys)

    tx = w3.eth.call.call_args.args[0]
    assert tx["to"] == CURRENT_COMMITTEE_ADDRESS
    selector = function_signature_to_4byte_selector("getCommitteeMembers()")
    assert tx["data"] == "0x" + selector.hex()


def test_get_committee_members_decodes_empty_public_keys():
    codec = Web3().codec
    w3 = _mock_w3(codec.encode(["uint64", "bytes32[]"], [7, []]))

    assert CurrentCommittee.get_committee_members(w3) == (7, ())


def test_get_committee_members_rejects_malformed_result():
    malformed = (
        (7).to_bytes(32, "big") + (64).to_bytes(32, "big") + (1).to_bytes(32, "big")
    )
    w3 = _mock_w3(malformed)

    with pytest.raises(DecodingError):
        CurrentCommittee.get_committee_members(w3)
