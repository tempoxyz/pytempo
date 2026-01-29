"""Tests for keychain module (precompile queries and access key signing)."""

from unittest.mock import MagicMock

import pytest
from eth_account import Account
from eth_utils import to_bytes

from pytempo import create_tempo_transaction
from pytempo.keychain import (
    # Constants
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_KEY_SELECTOR,
    GET_REMAINING_LIMIT_SELECTOR,
    INNER_SIGNATURE_LENGTH,
    KEY_AUTHORIZED_TOPIC,
    KEY_REVOKED_TOPIC,
    KEYCHAIN_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_TYPE,
    # Key authorization classes
    KeyAuthorization,
    SignatureType,
    SignedKeyAuthorization,
    TokenLimit,
    # Signing functions
    build_keychain_signature,
    create_key_authorization,
    # Precompile functions
    encode_get_remaining_limit_calldata,
    get_access_key_info,
    get_remaining_spending_limit,
    list_access_keys,
    sign_tx_access_key,
)


class TestPrecompileConstants:
    """Tests for precompile address constants."""

    def test_account_keychain_address_format(self):
        """Address should be valid checksummed hex."""
        assert ACCOUNT_KEYCHAIN_ADDRESS.startswith("0x")
        assert len(ACCOUNT_KEYCHAIN_ADDRESS) == 42

    def test_get_remaining_limit_selector(self):
        """Function selector should be 4 bytes (10 hex chars with 0x)."""
        assert GET_REMAINING_LIMIT_SELECTOR.startswith("0x")
        assert len(GET_REMAINING_LIMIT_SELECTOR) == 10

    def test_get_key_selector(self):
        """Function selector should be 4 bytes (10 hex chars with 0x)."""
        assert GET_KEY_SELECTOR.startswith("0x")
        assert len(GET_KEY_SELECTOR) == 10

    def test_key_authorized_topic(self):
        """Event topic should be 32 bytes (66 hex chars with 0x)."""
        assert KEY_AUTHORIZED_TOPIC.startswith("0x")
        assert len(KEY_AUTHORIZED_TOPIC) == 66

    def test_key_revoked_topic(self):
        """Event topic should be 32 bytes (66 hex chars with 0x)."""
        assert KEY_REVOKED_TOPIC.startswith("0x")
        assert len(KEY_REVOKED_TOPIC) == 66


class TestEncodeGetRemainingLimitCalldata:
    """Tests for calldata encoding."""

    def test_calldata_starts_with_selector(self):
        """Calldata should start with function selector."""
        calldata = encode_get_remaining_limit_calldata(
            "0x" + "a" * 40,
            "0x" + "b" * 40,
            "0x" + "c" * 40,
        )

        assert calldata.startswith(GET_REMAINING_LIMIT_SELECTOR)

    def test_calldata_length(self):
        """Calldata should be selector (4 bytes) + 3 addresses (32 bytes each)."""
        calldata = encode_get_remaining_limit_calldata(
            "0x" + "a" * 40,
            "0x" + "b" * 40,
            "0x" + "c" * 40,
        )

        # 0x + 8 (selector) + 64*3 (addresses) = 202 chars
        assert len(calldata) == 202

    def test_addresses_are_padded(self):
        """Each address should be zero-padded to 32 bytes."""
        calldata = encode_get_remaining_limit_calldata(
            "0x1234567890123456789012345678901234567890",
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
            "0x0000000000000000000000000000000000000001",
        )

        # Skip selector
        params = calldata[10:]

        # First param (account)
        assert params[:64] == "0" * 24 + "1234567890123456789012345678901234567890"

        # Second param (key_id)
        assert params[64:128] == "0" * 24 + "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

        # Third param (token)
        assert params[128:192] == "0" * 63 + "1"

    def test_lowercase_addresses(self):
        """Addresses should be lowercased in calldata."""
        calldata = encode_get_remaining_limit_calldata(
            "0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
            "0x1234567890ABCDEF1234567890ABCDEF12345678",
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        )

        assert "ABCDEF" not in calldata
        assert "abcdef" in calldata


class TestGetRemainingSpendingLimit:
    """Tests for querying spending limits."""

    def test_returns_int(self):
        """Should return an integer."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (1000000).to_bytes(32, "big")

        result = get_remaining_spending_limit(
            mock_w3,
            "0x" + "a" * 40,
            "0x" + "b" * 40,
            "0x" + "c" * 40,
        )

        assert isinstance(result, int)
        assert result == 1000000

    def test_parses_large_value(self):
        """Should handle large values correctly."""
        mock_w3 = MagicMock()
        large_value = 10**18  # 1 ETH worth
        mock_w3.eth.call.return_value = large_value.to_bytes(32, "big")

        result = get_remaining_spending_limit(
            mock_w3,
            "0x" + "a" * 40,
            "0x" + "b" * 40,
            "0x" + "c" * 40,
        )

        assert result == large_value

    def test_parses_zero(self):
        """Should handle zero correctly."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big")

        result = get_remaining_spending_limit(
            mock_w3,
            "0x" + "a" * 40,
            "0x" + "b" * 40,
            "0x" + "c" * 40,
        )

        assert result == 0

    def test_raises_on_empty_account(self):
        """Should raise ValueError if account_address is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            get_remaining_spending_limit(mock_w3, "", "0x" + "b" * 40, "0x" + "c" * 40)

    def test_raises_on_empty_key_id(self):
        """Should raise ValueError if key_id is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            get_remaining_spending_limit(mock_w3, "0x" + "a" * 40, "", "0x" + "c" * 40)

    def test_raises_on_empty_token(self):
        """Should raise ValueError if token_address is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            get_remaining_spending_limit(mock_w3, "0x" + "a" * 40, "0x" + "b" * 40, "")


class TestKeychainSignatureFormat:
    """Tests for Keychain signature format correctness."""

    def test_signature_length_is_86_bytes(self):
        """Keychain signature must be exactly 86 bytes."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        assert len(tx.signature) == KEYCHAIN_SIGNATURE_LENGTH
        assert len(tx.signature) == 86

    def test_signature_starts_with_0x03(self):
        """First byte must be 0x03 (Keychain type identifier)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        assert tx.signature[0] == KEYCHAIN_SIGNATURE_TYPE
        assert tx.signature[0] == 0x03

    def test_root_account_embedded_in_signature(self):
        """Bytes 1-21 must contain the root account address."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        embedded_address = tx.signature[1:21]
        expected_address = to_bytes(hexstr=root_account)

        assert embedded_address == expected_address

    def test_inner_signature_is_65_bytes(self):
        """Bytes 21-86 must be 65-byte inner signature (r || s || v)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        inner_sig = tx.signature[21:]
        assert len(inner_sig) == INNER_SIGNATURE_LENGTH
        assert len(inner_sig) == 65

    def test_vrs_cleared_after_signing(self):
        """v, r, s fields must be cleared since we use raw signature bytes."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        assert tx.v is None
        assert tx.r is None
        assert tx.s is None

    def test_sender_address_set_to_root_account(self):
        """tx.sender_address must be set to root account before hashing."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx, access_key_private, root_account)

        assert tx.sender_address == to_bytes(hexstr=root_account)


class TestKeychainVsNormalSigning:
    """Tests comparing Keychain signing to normal secp256k1 signing."""

    def test_different_signature_length(self):
        """Keychain signature (86 bytes) vs normal (65 bytes)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx1 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )
        tx2 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx1, access_key_private, root_account)
        tx2.sign(access_key_private)

        assert len(tx1.signature) == 86  # Keychain
        assert len(tx2.signature) == 65  # Normal secp256k1

    def test_different_type_prefix(self):
        """Keychain starts with 0x03, normal doesn't."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx1 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )
        tx2 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx1, access_key_private, root_account)
        tx2.sign(access_key_private)

        assert tx1.signature[0] == 0x03
        assert tx2.signature[0] != 0x03

    def test_encoded_transactions_different(self):
        """Encoded transactions should be different."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx1 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )
        tx2 = create_tempo_transaction(
            to="0x" + "c" * 40,
            value=1000,
            gas=21000,
            nonce=0,
            chain_id=42431,
        )

        sign_tx_access_key(tx1, access_key_private, root_account)
        tx2.sign(access_key_private)

        assert tx1.encode() != tx2.encode()


class TestBuildKeychainSignature:
    """Tests for the lower-level build_keychain_signature function."""

    def test_returns_bytes(self):
        """Should return bytes, not hex string."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40
        msg_hash = b"\x00" * 32

        sig = build_keychain_signature(msg_hash, access_key_private, root_account)

        assert isinstance(sig, bytes)

    def test_deterministic(self):
        """Same inputs should produce same signature."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40
        msg_hash = b"\x00" * 32

        sig1 = build_keychain_signature(msg_hash, access_key_private, root_account)
        sig2 = build_keychain_signature(msg_hash, access_key_private, root_account)

        assert sig1 == sig2

    def test_different_hash_different_signature(self):
        """Different message hashes should produce different signatures."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        sig1 = build_keychain_signature(b"\x00" * 32, access_key_private, root_account)
        sig2 = build_keychain_signature(b"\x01" * 32, access_key_private, root_account)

        # First 21 bytes (type + address) should be same
        assert sig1[:21] == sig2[:21]
        # Inner signature should be different
        assert sig1[21:] != sig2[21:]


class TestGetAccessKeyInfo:
    """Tests for get_access_key_info function."""

    def test_returns_empty_dict_on_empty_account(self):
        """Should return empty dict if account_address is empty."""
        mock_w3 = MagicMock()
        result = get_access_key_info(mock_w3, "", "0x" + "b" * 40)
        assert result == {}

    def test_returns_empty_dict_on_empty_key_id(self):
        """Should return empty dict if key_id is empty."""
        mock_w3 = MagicMock()
        result = get_access_key_info(mock_w3, "0x" + "a" * 40, "")
        assert result == {}

    def test_returns_empty_dict_when_account_equals_key_id(self):
        """Should return empty dict if account_address equals key_id."""
        mock_w3 = MagicMock()
        addr = "0x" + "a" * 40
        result = get_access_key_info(mock_w3, addr, addr)
        assert result == {}

    def test_returns_empty_dict_on_short_result(self):
        """Should return empty dict if result is too short."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 100  # Less than 160 bytes
        result = get_access_key_info(mock_w3, "0x" + "a" * 40, "0x" + "b" * 40)
        assert result == {}

    def test_returns_empty_dict_on_zero_address_key(self):
        """Should return empty dict if returned key_id is zero address."""
        mock_w3 = MagicMock()
        # Return: signatureType=0, keyId=0x0, expiry=0, enforceLimits=false, isRevoked=false
        mock_w3.eth.call.return_value = (
            (0).to_bytes(32, "big")
            + b"\x00" * 32  # zero address
            + (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
            + (0).to_bytes(32, "big")
        )
        result = get_access_key_info(mock_w3, "0x" + "a" * 40, "0x" + "b" * 40)
        assert result == {}

    def test_parses_valid_key_info(self):
        """Should correctly parse valid key info response."""
        mock_w3 = MagicMock()
        key_addr = "0x" + "b" * 40

        # Return: signatureType=1, keyId=key_addr, expiry=1893456000, enforceLimits=true, isRevoked=false
        mock_w3.eth.call.return_value = (
            (1).to_bytes(32, "big")  # P256
            + bytes(12)
            + bytes.fromhex("b" * 40)  # padded address
            + (1893456000).to_bytes(32, "big")  # expiry
            + (1).to_bytes(32, "big")  # enforceLimits=true
            + (0).to_bytes(32, "big")  # isRevoked=false
        )

        result = get_access_key_info(mock_w3, "0x" + "a" * 40, key_addr)

        assert result["signature_type"] == 1
        assert result["key_id"].lower() == key_addr.lower()
        assert result["expiry"] == 1893456000
        assert result["enforce_limits"] is True
        assert result["is_revoked"] is False

    def test_returns_empty_dict_on_exception(self):
        """Should return empty dict on any exception."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.side_effect = Exception("RPC error")
        result = get_access_key_info(mock_w3, "0x" + "a" * 40, "0x" + "b" * 40)
        assert result == {}


class TestListAccessKeys:
    """Tests for list_access_keys function."""

    def test_returns_empty_list_on_empty_account(self):
        """Should return empty list if account_address is empty."""
        mock_w3 = MagicMock()
        result = list_access_keys(mock_w3, "")
        assert result == []

    def test_returns_empty_list_on_no_logs(self):
        """Should return empty list if no KeyAuthorized events found."""
        mock_w3 = MagicMock()
        mock_w3.eth.get_logs.return_value = []
        result = list_access_keys(mock_w3, "0x" + "a" * 40)
        assert result == []

    def test_returns_empty_list_on_exception(self):
        """Should return empty list on any exception."""
        mock_w3 = MagicMock()
        mock_w3.eth.get_logs.side_effect = Exception("RPC error")
        result = list_access_keys(mock_w3, "0x" + "a" * 40)
        assert result == []

    def test_queries_correct_topics(self):
        """Should query with correct event topic and account filter."""
        mock_w3 = MagicMock()
        mock_w3.eth.get_logs.return_value = []
        account = "0x" + "a" * 40

        list_access_keys(mock_w3, account)

        call_args = mock_w3.eth.get_logs.call_args[0][0]
        assert call_args["topics"][0] == KEY_AUTHORIZED_TOPIC
        assert account[2:].lower() in call_args["topics"][1].lower()


class TestSignatureType:
    """Tests for SignatureType constants."""

    def test_secp256k1_is_zero(self):
        assert SignatureType.SECP256K1 == 0

    def test_p256_is_one(self):
        assert SignatureType.P256 == 1

    def test_webauthn_is_two(self):
        assert SignatureType.WEBAUTHN == 2


class TestTokenLimit:
    """Tests for TokenLimit dataclass."""

    def test_to_rlp(self):
        """Should convert to RLP-serializable format."""
        limit = TokenLimit(token="0x" + "a" * 40, limit=1000)
        rlp_obj = limit.to_rlp()

        assert rlp_obj.token == bytes.fromhex("a" * 40)
        assert rlp_obj.limit == 1000


class TestKeyAuthorization:
    """Tests for KeyAuthorization dataclass."""

    def test_rlp_encode_minimal(self):
        """Should RLP encode with minimal fields."""
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_rlp_encode_with_expiry(self):
        """Should RLP encode with expiry."""
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
            expiry=1893456000,
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)

    def test_rlp_encode_with_limits(self):
        """Should RLP encode with token limits."""
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
            limits=[TokenLimit(token="0x" + "c" * 40, limit=1000)],
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)

    def test_signature_hash_deterministic(self):
        """Should produce deterministic hash."""
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )

        hash1 = auth.signature_hash()
        hash2 = auth.signature_hash()

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_signature_hash_different_for_different_auth(self):
        """Different authorizations should have different hashes."""
        auth1 = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )
        auth2 = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "c" * 40,
        )

        assert auth1.signature_hash() != auth2.signature_hash()

    def test_sign_returns_signed_authorization(self):
        """Should return a SignedKeyAuthorization."""
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )

        signed = auth.sign(private_key)

        assert isinstance(signed, SignedKeyAuthorization)
        assert signed.authorization == auth
        assert signed.v in (27, 28)
        assert signed.r > 0
        assert signed.s > 0


class TestSignedKeyAuthorization:
    """Tests for SignedKeyAuthorization dataclass."""

    def test_rlp_encode(self):
        """Should RLP encode the signed authorization."""
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )
        signed = auth.sign(private_key)

        encoded = signed.rlp_encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_recover_signer(self):
        """Should recover the correct signer address."""
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            key_id="0x" + "b" * 40,
        )
        signed = auth.sign(private_key)

        recovered = signed.recover_signer()
        assert recovered.lower() == account.address.lower()

    def test_recover_signer_with_expiry_and_limits(self):
        """Should recover signer for auth with all fields."""
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        auth = KeyAuthorization(
            chain_id=42429,
            key_type=SignatureType.P256,
            key_id="0x" + "b" * 40,
            expiry=1893456000,
            limits=[TokenLimit(token="0x" + "c" * 40, limit=1000000)],
        )
        signed = auth.sign(private_key)

        recovered = signed.recover_signer()
        assert recovered.lower() == account.address.lower()


class TestCreateKeyAuthorization:
    """Tests for create_key_authorization helper function."""

    def test_creates_basic_authorization(self):
        """Should create a basic KeyAuthorization."""
        auth = create_key_authorization(key_id="0x" + "b" * 40)

        assert auth.chain_id == 0
        assert auth.key_type == SignatureType.SECP256K1
        assert auth.key_id == "0x" + "b" * 40
        assert auth.expiry is None
        assert auth.limits is None

    def test_creates_with_all_options(self):
        """Should create with all options specified."""
        auth = create_key_authorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.WEBAUTHN,
            expiry=1893456000,
            limits=[{"token": "0x" + "c" * 40, "limit": 1000}],
        )

        assert auth.chain_id == 42429
        assert auth.key_type == SignatureType.WEBAUTHN
        assert auth.expiry == 1893456000
        assert len(auth.limits) == 1
        assert auth.limits[0].token == "0x" + "c" * 40
        assert auth.limits[0].limit == 1000

    def test_sign_and_use_workflow(self):
        """Test the full workflow: create, sign, encode."""
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        # Create authorization
        auth = create_key_authorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            expiry=1893456000,
        )

        # Sign it
        signed = auth.sign(private_key)

        # Verify signer
        assert signed.recover_signer().lower() == account.address.lower()

        # Encode for transaction
        encoded = signed.rlp_encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0
