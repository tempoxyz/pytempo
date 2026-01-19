"""Tests for access key (Keychain) signing."""

import pytest
from eth_account import Account
from eth_utils import to_bytes

from pytempo import create_tempo_transaction
from pytempo.access_keys import (
    KEYCHAIN_SIGNATURE_TYPE,
    KEYCHAIN_SIGNATURE_LENGTH,
    INNER_SIGNATURE_LENGTH,
    build_keychain_signature,
    sign_tx_access_key,
)


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
