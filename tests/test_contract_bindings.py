"""Tests for typed contract call builders."""

from unittest.mock import MagicMock

import pytest
from eth_utils import function_signature_to_4byte_selector

from pytempo import KeyRestrictions
from pytempo.contracts import (
    ALPHA_USD,
    BETA_USD,
    TIP20,
    TIP20_ROLES_AUTH_ABI,
    Nonce,
    StablecoinDEX,
)
from pytempo.contracts.account_keychain import AccountKeychain
from pytempo.contracts.addresses import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    NONCE_ADDRESS,
    STABLECOIN_DEX_ADDRESS,
)
from pytempo.keychain import SignatureType

RECIPIENT = "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
ROLE = "0x" + "11" * 32
WITNESS = "0x" + "33" * 32


def _selector(signature: str) -> bytes:
    return function_signature_to_4byte_selector(signature)


def test_tip20_t5_builders_encode_expected_selectors():
    token = TIP20(ALPHA_USD)

    cases = [
        (
            token.burn_blocked(sender=RECIPIENT, amount=1),
            "burnBlocked(address,uint256)",
        ),
        (
            token.change_transfer_policy_id(new_policy_id=7),
            "changeTransferPolicyId(uint64)",
        ),
        (token.claim_rewards(), "claimRewards()"),
        (token.complete_quote_token_update(), "completeQuoteTokenUpdate()"),
        (token.distribute_reward(amount=10), "distributeReward(uint256)"),
        (token.pause(), "pause()"),
        (
            token.set_logo_uri(logo_uri="https://example.com/logo.png"),
            "setLogoURI(string)",
        ),
        (
            token.set_next_quote_token(new_quote_token=BETA_USD),
            "setNextQuoteToken(address)",
        ),
        (
            token.set_reward_recipient(new_reward_recipient=RECIPIENT),
            "setRewardRecipient(address)",
        ),
        (token.set_supply_cap(new_supply_cap=1_000_000), "setSupplyCap(uint256)"),
        (token.unpause(), "unpause()"),
        (token.grant_role(role=ROLE, account=RECIPIENT), "grantRole(bytes32,address)"),
        (
            token.revoke_role(role=ROLE, account=RECIPIENT),
            "revokeRole(bytes32,address)",
        ),
        (token.renounce_role(role=ROLE), "renounceRole(bytes32)"),
        (
            token.set_role_admin(role=ROLE, admin_role="0x" + "22" * 32),
            "setRoleAdmin(bytes32,bytes32)",
        ),
    ]

    for call, signature in cases:
        assert call.to == bytes.fromhex(ALPHA_USD[2:])
        assert call.data[:4] == _selector(signature)


def test_tip20_roles_auth_abi_is_exported():
    functions = {
        entry["name"]
        for entry in TIP20_ROLES_AUTH_ABI
        if entry.get("type") == "function"
    }

    assert functions == {
        "getRoleAdmin",
        "grantRole",
        "hasRole",
        "renounceRole",
        "revokeRole",
        "setRoleAdmin",
    }


def test_tip20_role_builder_rejects_invalid_role_length():
    token = TIP20(ALPHA_USD)

    with pytest.raises(ValueError, match="hash32"):
        token.grant_role(role="0x1234", account=RECIPIENT)


def test_tip20_role_query_helpers_decode_results_and_encode_selectors():
    token = TIP20(ALPHA_USD)
    mock_w3 = MagicMock()
    mock_w3.eth.call.side_effect = [
        bytes.fromhex("44" * 32),
        (1).to_bytes(32, "big"),
        bytes.fromhex("55" * 32),
        bytes.fromhex("66" * 32),
        bytes.fromhex("77" * 32),
        bytes.fromhex("88" * 32),
    ]

    assert token.get_role_admin(mock_w3, role=ROLE) == bytes.fromhex("44" * 32)
    assert token.has_role(mock_w3, role=ROLE, account=RECIPIENT) is True
    assert token.burn_blocked_role(mock_w3) == bytes.fromhex("55" * 32)
    assert token.issuer_role(mock_w3) == bytes.fromhex("66" * 32)
    assert token.pause_role(mock_w3) == bytes.fromhex("77" * 32)
    assert token.unpause_role(mock_w3) == bytes.fromhex("88" * 32)

    expected = [
        "getRoleAdmin(bytes32)",
        "hasRole(address,bytes32)",
        "BURN_BLOCKED_ROLE()",
        "ISSUER_ROLE()",
        "PAUSE_ROLE()",
        "UNPAUSE_ROLE()",
    ]
    assert len(mock_w3.eth.call.call_args_list) == len(expected)
    for call, signature in zip(mock_w3.eth.call.call_args_list, expected):
        tx = call.args[0]
        assert tx["to"] == ALPHA_USD
        assert bytes.fromhex(tx["data"][2:10]) == _selector(signature)


def test_tip20_has_role_rejects_noncanonical_bool():
    token = TIP20(ALPHA_USD)
    mock_w3 = MagicMock()
    mock_w3.eth.call.return_value = (2).to_bytes(32, "big")

    with pytest.raises(ValueError, match="ABI bool"):
        token.has_role(mock_w3, role=ROLE, account=RECIPIENT)


def test_account_keychain_t5_builders_encode_expected_selectors():
    restrictions = KeyRestrictions()

    cases = [
        (
            AccountKeychain.authorize_admin_key(
                key_id=RECIPIENT,
                signature_type=SignatureType.SECP256K1,
                witness=WITNESS,
            ),
            "authorizeAdminKey(address,uint8,bytes32)",
        ),
        (
            AccountKeychain.authorize_key(
                key_id=RECIPIENT,
                signature_type=SignatureType.SECP256K1,
                restrictions=restrictions,
            ),
            "authorizeKey(address,uint8,(uint64,bool,(address,uint256,uint64)[],bool,(address,(bytes4,address[])[])[]))",
        ),
        (
            AccountKeychain.authorize_key(
                key_id=RECIPIENT,
                signature_type=SignatureType.SECP256K1,
                restrictions=restrictions,
                witness=WITNESS,
            ),
            "authorizeKey(address,uint8,(uint64,bool,(address,uint256,uint64)[],bool,(address,(bytes4,address[])[])[]),bytes32)",
        ),
        (
            AccountKeychain.burn_key_authorization_witness(witness=WITNESS),
            "burnKeyAuthorizationWitness(bytes32)",
        ),
    ]

    for call, signature in cases:
        assert call.to == bytes.fromhex(ACCOUNT_KEYCHAIN_ADDRESS[2:])
        assert call.data[:4] == _selector(signature)


def test_account_keychain_t5_builders_reject_invalid_witness_length():
    with pytest.raises(ValueError, match="hash32"):
        AccountKeychain.authorize_admin_key(
            key_id=RECIPIENT,
            signature_type=SignatureType.SECP256K1,
            witness="0x1234",
        )


def test_account_keychain_authorize_admin_key_rejects_empty_key_id():
    with pytest.raises(ValueError, match="key_id"):
        AccountKeychain.authorize_admin_key(
            key_id="",
            signature_type=SignatureType.SECP256K1,
            witness=WITNESS,
        )


def test_account_keychain_legacy_authorize_key_rejects_witness():
    with pytest.raises(ValueError, match="witnesses"):
        AccountKeychain.authorize_key(
            key_id=RECIPIENT,
            signature_type=SignatureType.SECP256K1,
            restrictions=KeyRestrictions(),
            legacy=True,
            witness=WITNESS,
        )


def test_nonce_get_nonce_rejects_empty_response():
    mock_w3 = MagicMock()
    mock_w3.eth.call.return_value = b""

    with pytest.raises(ValueError, match="wrong length"):
        Nonce.get_nonce(mock_w3, account=RECIPIENT, nonce_key=0)

    tx = mock_w3.eth.call.call_args.args[0]
    assert tx["to"] == NONCE_ADDRESS
    assert bytes.fromhex(tx["data"][2:10]) == _selector("getNonce(address,uint256)")


def test_dex_storage_credits_decodes_and_encodes_selector():
    mock_w3 = MagicMock()
    mock_w3.eth.call.return_value = (7).to_bytes(32, "big")

    assert StablecoinDEX.storage_credits(mock_w3, user=RECIPIENT) == 7

    tx = mock_w3.eth.call.call_args.args[0]
    assert tx["to"] == STABLECOIN_DEX_ADDRESS
    assert bytes.fromhex(tx["data"][2:10]) == _selector("storageCredits(address)")
    # the user address is encoded (left-padded to 32 bytes) into the calldata
    assert tx["data"][10:].lower() == ("0" * 24) + RECIPIENT[2:].lower()


def test_dex_storage_credits_rejects_empty_user():
    with pytest.raises(ValueError, match="user required"):
        StablecoinDEX.storage_credits(MagicMock(), user="")


def test_dex_storage_credits_rejects_overflow():
    mock_w3 = MagicMock()
    mock_w3.eth.call.return_value = (2**64).to_bytes(32, "big")

    with pytest.raises(ValueError, match="uint64"):
        StablecoinDEX.storage_credits(mock_w3, user=RECIPIENT)
