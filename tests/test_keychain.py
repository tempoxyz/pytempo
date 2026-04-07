"""Tests for keychain module (precompile queries and access key signing)."""

from unittest.mock import MagicMock

import pytest
from eth_account import Account
from eth_utils import to_bytes

from pytempo import Call, CallScope, SelectorRule, TempoTransaction
from pytempo.contracts import ALPHA_USD
from pytempo.contracts.account_keychain import AccountKeychain
from pytempo.contracts.addresses import ACCOUNT_KEYCHAIN_ADDRESS
from pytempo.keychain import (
    # Constants
    INNER_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_LENGTH,
    KEYCHAIN_SIGNATURE_TYPE,
    # Key authorization classes
    KeyAuthorization,
    KeychainSignature,
    SignatureType,
    SignedKeyAuthorization,
    TokenLimit,
    # Signing functions (deprecated wrappers)
    build_keychain_signature,
    create_key_authorization,
    sign_tx_access_key,
)


class TestPrecompileConstants:
    """Tests for precompile address constants."""

    def test_account_keychain_address_format(self):
        """Address should be valid checksummed hex."""
        assert ACCOUNT_KEYCHAIN_ADDRESS.startswith("0x")
        assert len(ACCOUNT_KEYCHAIN_ADDRESS) == 42


class TestGetRemainingLimit:
    """Tests for AccountKeychain.get_remaining_limit."""

    def test_returns_int(self):
        """Should return an integer."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (1000000).to_bytes(32, "big")

        result = AccountKeychain.get_remaining_limit(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
            token_address="0x" + "c" * 40,
        )

        assert isinstance(result, int)
        assert result == 1000000

    def test_parses_large_value(self):
        """Should handle large values correctly."""
        mock_w3 = MagicMock()
        large_value = 10**18  # 1 ETH worth
        mock_w3.eth.call.return_value = large_value.to_bytes(32, "big")

        result = AccountKeychain.get_remaining_limit(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
            token_address="0x" + "c" * 40,
        )

        assert result == large_value

    def test_parses_zero(self):
        """Should handle zero correctly."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = (0).to_bytes(32, "big")

        result = AccountKeychain.get_remaining_limit(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
            token_address="0x" + "c" * 40,
        )

        assert result == 0

    def test_raises_on_empty_account(self):
        """Should raise ValueError if account_address is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            AccountKeychain.get_remaining_limit(
                mock_w3,
                account_address="",
                key_id="0x" + "b" * 40,
                token_address="0x" + "c" * 40,
            )

    def test_raises_on_empty_key_id(self):
        """Should raise ValueError if key_id is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            AccountKeychain.get_remaining_limit(
                mock_w3,
                account_address="0x" + "a" * 40,
                key_id="",
                token_address="0x" + "c" * 40,
            )

    def test_raises_on_empty_token(self):
        """Should raise ValueError if token_address is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            AccountKeychain.get_remaining_limit(
                mock_w3,
                account_address="0x" + "a" * 40,
                key_id="0x" + "b" * 40,
                token_address="",
            )


class TestGetKey:
    """Tests for AccountKeychain.get_key."""

    def _build_result(
        self,
        sig_type=0,
        key_id_hex="b" * 40,
        expiry=1893456000,
        enforce_limits=0,
        is_revoked=0,
    ):
        key_id = bytes.fromhex(key_id_hex)
        return (
            sig_type.to_bytes(32, "big")
            + (b"\x00" * 12 + key_id)
            + expiry.to_bytes(32, "big")
            + enforce_limits.to_bytes(32, "big")
            + is_revoked.to_bytes(32, "big")
        )

    def test_parses_key_info(self):
        """Should parse getKey result into a dict."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = self._build_result()

        info = AccountKeychain.get_key(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
        )

        assert info["signature_type"] == 0
        assert info["key_id"].lower() == ("0x" + "b" * 40).lower()
        assert info["expiry"] == 1893456000
        assert info["enforce_limits"] is False
        assert info["is_revoked"] is False

    def test_parses_p256_signature_type(self):
        """Should decode non-zero signature types."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = self._build_result(sig_type=1)

        info = AccountKeychain.get_key(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
        )

        assert info["signature_type"] == 1

    def test_parses_revoked_key(self):
        """Should detect revoked keys."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = self._build_result(is_revoked=1)

        info = AccountKeychain.get_key(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
        )

        assert info["is_revoked"] is True

    def test_parses_enforce_limits(self):
        """Should detect enforce_limits=true."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = self._build_result(enforce_limits=1)

        info = AccountKeychain.get_key(
            mock_w3,
            account_address="0x" + "a" * 40,
            key_id="0x" + "b" * 40,
        )

        assert info["enforce_limits"] is True

    def test_raises_on_empty_account(self):
        """Should raise ValueError if account_address is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            AccountKeychain.get_key(
                mock_w3,
                account_address="",
                key_id="0x" + "b" * 40,
            )

    def test_raises_on_empty_key_id(self):
        """Should raise ValueError if key_id is empty."""
        mock_w3 = MagicMock()

        with pytest.raises(ValueError):
            AccountKeychain.get_key(
                mock_w3,
                account_address="0x" + "a" * 40,
                key_id="",
            )

    def test_raises_on_short_result(self):
        """Should raise ValueError if result is too short."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 100

        with pytest.raises(ValueError, match="wrong length"):
            AccountKeychain.get_key(
                mock_w3,
                account_address="0x" + "a" * 40,
                key_id="0x" + "b" * 40,
            )

    def test_raises_on_long_result(self):
        """Should raise ValueError if result is too long."""
        mock_w3 = MagicMock()
        mock_w3.eth.call.return_value = b"\x00" * 192

        with pytest.raises(ValueError, match="wrong length"):
            AccountKeychain.get_key(
                mock_w3,
                account_address="0x" + "a" * 40,
                key_id="0x" + "b" * 40,
            )


class TestKeychainSignatureFormat:
    """Tests for Keychain signature format correctness."""

    def test_signature_length_is_86_bytes(self):
        """Keychain signature must be exactly 86 bytes."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = tx.sign_access_key(access_key_private, root_account)

        sig = signed.sender_signature
        assert isinstance(sig, KeychainSignature)
        assert len(sig.to_bytes()) == KEYCHAIN_SIGNATURE_LENGTH
        assert len(sig.to_bytes()) == 86

    def test_signature_starts_with_0x04(self):
        """First byte must be 0x04 (Keychain V2 type identifier)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = tx.sign_access_key(access_key_private, root_account)

        sig_bytes = signed.sender_signature.to_bytes()
        assert sig_bytes[0] == KEYCHAIN_SIGNATURE_TYPE
        assert sig_bytes[0] == 0x04

    def test_root_account_embedded_in_signature(self):
        """Bytes 1-21 must contain the root account address."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = tx.sign_access_key(access_key_private, root_account)

        sig = signed.sender_signature
        assert isinstance(sig, KeychainSignature)
        assert bytes(sig.root_account) == to_bytes(hexstr=root_account)

    def test_inner_signature_is_65_bytes(self):
        """Inner signature must be 65 bytes (r || s || v)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = tx.sign_access_key(access_key_private, root_account)

        sig = signed.sender_signature
        assert isinstance(sig, KeychainSignature)
        assert len(sig.inner.to_bytes()) == INNER_SIGNATURE_LENGTH
        assert len(sig.inner.to_bytes()) == 65

    def test_sender_address_set_to_root_account(self):
        """sender_address must be set to root account."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = tx.sign_access_key(access_key_private, root_account)

        assert bytes(signed.sender_address) == to_bytes(hexstr=root_account)


class TestKeychainVsNormalSigning:
    """Tests comparing Keychain signing to normal secp256k1 signing."""

    def test_different_signature_length(self):
        """Keychain signature (86 bytes) vs normal (65 bytes)."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        keychain_signed = tx.sign_access_key(access_key_private, root_account)
        normal_signed = tx.sign(access_key_private)

        assert len(keychain_signed.sender_signature.to_bytes()) == 86  # Keychain
        assert len(normal_signed.sender_signature.to_bytes()) == 65  # Normal secp256k1

    def test_different_type_prefix(self):
        """Keychain starts with 0x04, normal doesn't."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        keychain_signed = tx.sign_access_key(access_key_private, root_account)
        normal_signed = tx.sign(access_key_private)

        assert keychain_signed.sender_signature.to_bytes()[0] == 0x04
        assert normal_signed.sender_signature.to_bytes()[0] != 0x04

    def test_both_produce_valid_encoded_tx(self):
        """Both signing methods should produce a valid encoded tx."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        keychain_signed = tx.sign_access_key(access_key_private, root_account)
        normal_signed = tx.sign(access_key_private)

        assert keychain_signed.encode() != normal_signed.encode()
        assert keychain_signed.encode()[0] == 0x76
        assert normal_signed.encode()[0] == 0x76


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


class TestKeychainSignatureType:
    """Tests for KeychainSignature structured type."""

    def test_roundtrip_bytes(self):
        """to_bytes / from_bytes roundtrip should preserve data."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40
        msg_hash = b"\x00" * 32

        sig = KeychainSignature.sign(msg_hash, access_key_private, root_account)
        raw = sig.to_bytes()
        parsed = KeychainSignature.from_bytes(raw)

        assert bytes(parsed.root_account) == bytes(sig.root_account)
        assert parsed.inner == sig.inner

    def test_from_bytes_rejects_wrong_length(self):
        with pytest.raises(ValueError, match="86 bytes"):
            KeychainSignature.from_bytes(b"\x00" * 85)

    def test_from_bytes_rejects_wrong_type_byte(self):
        raw = b"\x05" + b"\x00" * 85
        with pytest.raises(ValueError, match="0x04"):
            KeychainSignature.from_bytes(raw)

    def test_frozen(self):
        """KeychainSignature should be immutable."""
        sig = KeychainSignature.sign(b"\x00" * 32, "0x" + "a" * 64, "0x" + "b" * 40)
        with pytest.raises(AttributeError):
            sig.root_account = b"\x00" * 20  # type: ignore[misc]


class TestSignatureType:
    """Tests for SignatureType enum."""

    def test_secp256k1_is_zero(self):
        assert SignatureType.SECP256K1 == 0

    def test_p256_is_one(self):
        assert SignatureType.P256 == 1

    def test_webauthn_is_two(self):
        assert SignatureType.WEBAUTHN == 2

    def test_rejects_invalid_value(self):
        with pytest.raises(ValueError):
            SignatureType(999)

    def test_json_names(self):
        assert SignatureType.SECP256K1.to_json_name() == "secp256k1"
        assert SignatureType.P256.to_json_name() == "p256"
        assert SignatureType.WEBAUTHN.to_json_name() == "webAuthn"


class TestTokenLimit:
    """Tests for TokenLimit attrs model."""

    def test_accepts_hex_string(self):
        """Should convert hex string to Address."""
        limit = TokenLimit(token="0x" + "a" * 40, limit=1000)
        assert bytes(limit.token) == bytes.fromhex("a" * 40)
        assert limit.limit == 1000

    def test_rejects_empty_token(self):
        with pytest.raises(ValueError, match="20 bytes"):
            TokenLimit(token="0x", limit=1000)

    def test_rejects_negative_limit(self):
        with pytest.raises(ValueError):
            TokenLimit(token="0x" + "a" * 40, limit=-1)

    def test_frozen(self):
        limit = TokenLimit(token="0x" + "a" * 40, limit=1000)
        with pytest.raises(AttributeError):
            limit.limit = 2000  # type: ignore[misc]


class TestKeyAuthorization:
    """Tests for KeyAuthorization attrs model."""

    def test_rlp_encode_minimal(self):
        """Should RLP encode with minimal fields."""
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_rlp_encode_with_expiry(self):
        """Should RLP encode with expiry."""
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            expiry=1893456000,
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)

    def test_rlp_encode_with_limits(self):
        """Should RLP encode with token limits."""
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            limits=[TokenLimit(token="0x" + "c" * 40, limit=1000)],
        )

        encoded = auth.rlp_encode()
        assert isinstance(encoded, bytes)

    def test_signature_hash_deterministic(self):
        """Should produce deterministic hash."""
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )

        hash1 = auth.signature_hash()
        hash2 = auth.signature_hash()

        assert hash1 == hash2
        assert len(hash1) == 32

    def test_signature_hash_different_for_different_auth(self):
        """Different authorizations should have different hashes."""
        auth1 = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )
        auth2 = KeyAuthorization(
            key_id="0x" + "c" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )

        assert auth1.signature_hash() != auth2.signature_hash()

    def test_sign_returns_signed_authorization(self):
        """Should return a SignedKeyAuthorization."""
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )

        signed = auth.sign(private_key)

        assert isinstance(signed, SignedKeyAuthorization)
        assert signed.authorization == auth
        assert signed.signature.v in (27, 28)
        assert signed.signature.r > 0
        assert signed.signature.s > 0

    def test_rejects_empty_key_id(self):
        with pytest.raises(ValueError, match="20 bytes"):
            KeyAuthorization(key_id="0x")

    def test_rejects_invalid_key_type(self):
        with pytest.raises(ValueError):
            KeyAuthorization(key_id="0x" + "b" * 40, key_type=999)

    def test_converter_accepts_int_key_type(self):
        """IntEnum converter should accept plain ints for valid values."""
        auth = KeyAuthorization(key_id="0x" + "b" * 40, key_type=1)
        assert auth.key_type is SignatureType.P256

    def test_frozen(self):
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
        )
        with pytest.raises(AttributeError):
            auth.chain_id = 1  # type: ignore[misc]


class TestSignedKeyAuthorization:
    """Tests for SignedKeyAuthorization attrs model."""

    def test_rlp_encode(self):
        """Should RLP encode the signed authorization."""
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
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
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
        )
        signed = auth.sign(private_key)

        recovered = signed.recover_signer()
        assert recovered.lower() == account.address.lower()

    def test_recover_signer_with_expiry_and_limits(self):
        """Should recover signer for auth with all fields."""
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.P256,
            expiry=1893456000,
            limits=[TokenLimit(token="0x" + "c" * 40, limit=1000000)],
        )
        signed = auth.sign(private_key)

        recovered = signed.recover_signer()
        assert recovered.lower() == account.address.lower()

    def test_to_json(self):
        """Should produce valid JSON dict."""
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            expiry=1893456000,
            limits=[TokenLimit(token="0x" + "c" * 40, limit=1000)],
        )
        signed = auth.sign(private_key)
        j = signed.to_json()

        assert j["keyType"] == "secp256k1"
        assert "signature" in j
        assert "expiry" in j
        assert "limits" in j
        assert len(j["limits"]) == 1

    def test_frozen(self):
        private_key = "0x" + "a" * 64
        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
        )
        signed = auth.sign(private_key)
        with pytest.raises(AttributeError):
            signed.authorization = None  # type: ignore[misc]


class TestSignTxWorkflow:
    """Tests for the full sign → encode workflow."""

    def test_sign_and_use_workflow(self):
        """Test the full workflow: create, sign, encode."""
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            expiry=1893456000,
        )

        signed = auth.sign(private_key)

        assert signed.recover_signer().lower() == account.address.lower()

        encoded = signed.rlp_encode()
        assert isinstance(encoded, bytes)
        assert len(encoded) > 0

    def test_deprecated_sign_tx_access_key(self):
        """Deprecated wrapper should still work."""
        access_key_private = "0x" + "a" * 64
        root_account = "0x" + "b" * 40

        tx = TempoTransaction.create(
            chain_id=42431,
            gas_limit=21000,
            nonce=0,
            calls=(Call.create(to="0x" + "c" * 40, value=1000),),
        )

        signed = sign_tx_access_key(tx, access_key_private, root_account)
        assert isinstance(signed.sender_signature, KeychainSignature)
        assert len(signed.sender_signature.to_bytes()) == 86


class TestCallScopeConstructors:
    """Tests for CallScope named constructors."""

    def test_transfer_selector(self):
        s = CallScope.transfer(target=ALPHA_USD)
        assert bytes(s.selector) == bytes.fromhex("a9059cbb")

    def test_approve_selector(self):
        s = CallScope.approve(target=ALPHA_USD)
        assert bytes(s.selector) == bytes.fromhex("095ea7b3")

    def test_transfer_with_memo_selector(self):
        s = CallScope.transfer_with_memo(target=ALPHA_USD)
        assert bytes(s.selector) == bytes.fromhex("95777d59")

    def test_unrestricted_selector(self):
        s = CallScope.unrestricted(target="0x" + "aa" * 20)
        assert bytes(s.selector) == b"\x00\x00\x00\x00"

    def test_unrestricted_allows_tip20(self):
        s = CallScope.unrestricted(target=ALPHA_USD)
        assert bytes(s.target).startswith(bytes.fromhex("20C000000000000000000000"))

    def test_tip20_rejects_non_tip20_address(self):
        with pytest.raises(ValueError, match="TIP20"):
            CallScope.transfer(target="0x" + "aa" * 20)

    def test_frozen(self):
        s = CallScope.transfer(target=ALPHA_USD)
        with pytest.raises(AttributeError):
            s.selector = b"\x00" * 4  # type: ignore[misc]

    def test_with_selector(self):
        target = "0x" + "aa" * 20
        sel = bytes.fromhex("aabbccdd")
        s = CallScope.with_selector(target=target, selector=sel)
        assert bytes(s.selector) == sel
        assert len(s.selector_rules) == 1
        assert s.selector_rules[0].recipients == ()

    def test_with_selector_and_recipients(self):
        target = "0x" + "aa" * 20
        sel = bytes.fromhex("aabbccdd")
        recipient = "0x" + "bb" * 20
        s = CallScope.with_selector(target=target, selector=sel, recipients=[recipient])
        assert len(s.selector_rules) == 1
        assert len(s.selector_rules[0].recipients) == 1

    def test_transfer_with_recipients(self):
        recipient = "0x" + "bb" * 20
        s = CallScope.transfer(target=ALPHA_USD, recipients=[recipient])
        assert len(s.selector_rules) == 1
        assert len(s.selector_rules[0].recipients) == 1

    def test_to_abi_tuple_fallback(self):
        """CallScope without selector_rules falls back to selector field."""
        s = CallScope(target="0x" + "aa" * 20, selector=bytes.fromhex("aabbccdd"))
        target_bytes, rules = s.to_abi_tuple()
        assert len(rules) == 1
        assert rules[0][0] == bytes.fromhex("aabbccdd")
        assert rules[0][1] == []

    def test_to_abi_tuple_with_rules(self):
        """CallScope with selector_rules uses them directly."""
        recipient = "0x" + "bb" * 20
        s = CallScope.transfer(target=ALPHA_USD, recipients=[recipient])
        target_bytes, rules = s.to_abi_tuple()
        assert len(rules) == 1
        assert rules[0][0] == bytes.fromhex("a9059cbb")
        assert len(rules[0][1]) == 1


class TestSelectorRule:
    """Tests for SelectorRule."""

    def test_empty_recipients(self):
        r = SelectorRule(selector=bytes.fromhex("aabbccdd"))
        assert r.recipients == ()

    def test_with_recipients(self):
        addr = "0x" + "aa" * 20
        r = SelectorRule(selector=bytes.fromhex("aabbccdd"), recipients=[addr])
        assert len(r.recipients) == 1

    def test_frozen(self):
        r = SelectorRule(selector=bytes.fromhex("aabbccdd"))
        with pytest.raises(AttributeError):
            r.selector = b"\x00" * 4  # type: ignore[misc]


class TestSetAndRemoveAllowedCalls:
    """Tests for AccountKeychain.set_allowed_calls and remove_allowed_calls."""

    def test_set_allowed_calls_encodes(self):
        key_id = "0x" + "11" * 20
        scope = CallScope.transfer(target=ALPHA_USD)
        call = AccountKeychain.set_allowed_calls(key_id=key_id, scopes=[scope])
        assert call.to is not None
        assert call.data is not None

    def test_remove_allowed_calls_encodes(self):
        key_id = "0x" + "11" * 20
        target = "0x" + "22" * 20
        call = AccountKeychain.remove_allowed_calls(key_id=key_id, target=target)
        assert call.to is not None
        assert call.data is not None

    def test_set_allowed_calls_with_recipients(self):
        key_id = "0x" + "11" * 20
        recipient = "0x" + "33" * 20
        scope = CallScope.transfer(target=ALPHA_USD, recipients=[recipient])
        call = AccountKeychain.set_allowed_calls(key_id=key_id, scopes=[scope])
        assert call.data is not None

    def test_set_allowed_calls_with_selector(self):
        key_id = "0x" + "11" * 20
        scope = CallScope.with_selector(
            target="0x" + "22" * 20,
            selector=bytes.fromhex("aabbccdd"),
        )
        call = AccountKeychain.set_allowed_calls(key_id=key_id, scopes=[scope])
        assert call.data is not None


class TestAuthorizeKeyGuards:
    """Tests for authorize_key argument validation."""

    def test_rejects_allowed_calls_with_allow_any_calls_true(self):
        scope = CallScope.transfer(target=ALPHA_USD)
        with pytest.raises(ValueError, match="allow_any_calls"):
            AccountKeychain.authorize_key(
                key_id="0x" + "11" * 20,
                signature_type=SignatureType.SECP256K1,
                expiry=2**64 - 1,
                allowed_calls=[scope],
            )

    def test_rejects_legacy_with_call_restrictions(self):
        scope = CallScope.transfer(target=ALPHA_USD)
        with pytest.raises(ValueError, match="legacy"):
            AccountKeychain.authorize_key(
                key_id="0x" + "11" * 20,
                signature_type=SignatureType.SECP256K1,
                expiry=2**64 - 1,
                allowed_calls=[scope],
                allow_any_calls=False,
                legacy=True,
            )

    def test_accepts_allowed_calls_with_allow_any_calls_false(self):
        scope = CallScope.transfer(target=ALPHA_USD)
        call = AccountKeychain.authorize_key(
            key_id="0x" + "11" * 20,
            signature_type=SignatureType.SECP256K1,
            expiry=2**64 - 1,
            allowed_calls=[scope],
            allow_any_calls=False,
        )
        assert call.data is not None


class TestRecoverSigner:
    """Tests for SignedKeyAuthorization.recover_signer."""

    def test_roundtrip(self):
        private_key = "0x" + "a" * 64
        account = Account.from_key(private_key)

        auth = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
        )
        signed = auth.sign(private_key)
        assert signed.recover_signer().lower() == account.address.lower()


class TestDeprecatedVrsShims:
    """Tests for v/r/s property shims on SignedKeyAuthorization."""

    def test_v_r_s_match_signature(self):
        auth = KeyAuthorization(key_id="0x" + "b" * 40, chain_id=42429)
        signed = auth.sign("0x" + "a" * 64)

        assert signed.v == signed.signature.v
        assert signed.r == signed.signature.r
        assert signed.s == signed.signature.s


class TestCreateKeyAuthorizationCompat:
    """Tests for deprecated create_key_authorization wrapper."""

    def test_matches_direct_construction(self):
        via_wrapper = create_key_authorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            expiry=1893456000,
            limits=[{"token": "0x" + "c" * 40, "limit": 1000}],
        )
        via_direct = KeyAuthorization(
            key_id="0x" + "b" * 40,
            chain_id=42429,
            key_type=SignatureType.SECP256K1,
            expiry=1893456000,
            limits=(TokenLimit(token="0x" + "c" * 40, limit=1000),),
        )
        assert via_wrapper.rlp_encode() == via_direct.rlp_encode()
