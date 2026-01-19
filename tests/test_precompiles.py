"""Tests for precompile utilities."""

import pytest
from unittest.mock import MagicMock

from pytempo.precompiles import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    GET_REMAINING_LIMIT_SELECTOR,
    encode_get_remaining_limit_calldata,
    get_remaining_spending_limit,
    format_spending_limit,
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
        mock_w3.eth.call.return_value = (1000000).to_bytes(32, 'big')
        
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
        mock_w3.eth.call.return_value = large_value.to_bytes(32, 'big')
        
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
        mock_w3.eth.call.return_value = (0).to_bytes(32, 'big')
        
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


class TestFormatSpendingLimit:
    """Tests for formatting spending limits."""
    
    def test_format_zero(self):
        """Zero should format as $0."""
        assert format_spending_limit(0) == "$0"
    
    def test_format_one_dollar(self):
        """1 million base units (6 decimals) = $1.00."""
        assert format_spending_limit(1_000_000) == "$1.00"
    
    def test_format_cents(self):
        """Small amounts should show cents."""
        assert format_spending_limit(500_000) == "$0.50"
        assert format_spending_limit(10_000) == "$0.01"
        assert format_spending_limit(1_000) == "$0.00"  # Rounds down
    
    def test_format_large_amount(self):
        """Large amounts should format correctly."""
        assert format_spending_limit(100_000_000) == "$100.00"
        assert format_spending_limit(1_000_000_000) == "$1000.00"
    
    def test_format_unlimited(self):
        """Very large values (>= 2^128) should show infinity."""
        assert format_spending_limit(2**128) == "∞"
        assert format_spending_limit(2**256 - 1) == "∞"
    
    def test_format_custom_decimals_18(self):
        """Test with 18 decimals (like ETH)."""
        assert format_spending_limit(1_000_000_000_000_000_000, decimals=18) == "$1.00"
    
    def test_format_custom_decimals_8(self):
        """Test with 8 decimals (like BTC)."""
        assert format_spending_limit(100_000_000, decimals=8) == "$1.00"
