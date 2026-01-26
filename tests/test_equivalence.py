"""
Equivalence tests between legacy and typed APIs.

These tests verify that both APIs produce identical results for the same inputs.
"""

import pytest

from pytempo import Call, TempoTransaction, create_tempo_transaction

# Test private key for signing
TEST_PRIVATE_KEY = "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"

# Common addresses used in tests
ADDR_A = "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55"
ADDR_B = "0x" + "b" * 40
ADDR_C = "0x" + "c" * 40
FEE_TOKEN = "0x20c0000000000000000000000000000000000001"


EQUIVALENCE_TEST_CASES = [
    # -------------------------------------------------------------------------
    # Basic transactions
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "minimal_transaction",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=21000,
                max_fee_per_gas=0,
                max_priority_fee_per_gas=0,
                nonce=0,
                chain_id=1,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=1,
                gas_limit=21000,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="minimal_transaction",
    ),
    pytest.param(
        {
            "name": "basic_with_value",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=1000000000000000,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=5,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=5,
                calls=(Call.create(to=ADDR_A, value=1000000000000000),),
            ),
        },
        id="basic_with_value",
    ),
    pytest.param(
        {
            "name": "with_data",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                data="0xabcdef1234567890",
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                calls=(Call.create(to=ADDR_A, value=0, data="0xabcdef1234567890"),),
            ),
        },
        id="with_data",
    ),
    # -------------------------------------------------------------------------
    # Fee token
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "with_fee_token",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
                fee_token=FEE_TOKEN,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                fee_token=FEE_TOKEN,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="with_fee_token",
    ),
    # -------------------------------------------------------------------------
    # 2D nonces
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "with_nonce_key",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=10,
                nonce_key=5,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=10,
                nonce_key=5,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="with_nonce_key",
    ),
    # -------------------------------------------------------------------------
    # Validity window
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "with_valid_before",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
                valid_before=1800000000,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                valid_before=1800000000,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="with_valid_before",
    ),
    pytest.param(
        {
            "name": "with_valid_after",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
                valid_after=1700000000,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                valid_after=1700000000,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="with_valid_after",
    ),
    pytest.param(
        {
            "name": "with_validity_window",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=0,
                gas=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
                valid_after=1700000000,
                valid_before=1800000000,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=100000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                valid_after=1700000000,
                valid_before=1800000000,
                calls=(Call.create(to=ADDR_A, value=0),),
            ),
        },
        id="with_validity_window",
    ),
    # -------------------------------------------------------------------------
    # Batch calls
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "batch_two_calls",
            "legacy": lambda: create_tempo_transaction(
                to="",
                calls=[
                    {"to": ADDR_A, "value": 100, "data": "0x"},
                    {"to": ADDR_B, "value": 200, "data": "0x"},
                ],
                gas=200000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=200000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                calls=(
                    Call.create(to=ADDR_A, value=100),
                    Call.create(to=ADDR_B, value=200),
                ),
            ),
        },
        id="batch_two_calls",
    ),
    pytest.param(
        {
            "name": "batch_three_calls_with_data",
            "legacy": lambda: create_tempo_transaction(
                to="",
                calls=[
                    {"to": ADDR_A, "value": 0, "data": "0xaabbcc"},
                    {"to": ADDR_B, "value": 1000, "data": "0xddeeff"},
                    {"to": ADDR_C, "value": 2000, "data": "0x112233"},
                ],
                gas=300000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=300000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                calls=(
                    Call.create(to=ADDR_A, value=0, data="0xaabbcc"),
                    Call.create(to=ADDR_B, value=1000, data="0xddeeff"),
                    Call.create(to=ADDR_C, value=2000, data="0x112233"),
                ),
            ),
        },
        id="batch_three_calls_with_data",
    ),
    # -------------------------------------------------------------------------
    # Contract creation
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "contract_creation",
            "legacy": lambda: create_tempo_transaction(
                to="",
                value=0,
                data="0x6080604052",
                gas=500000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                nonce=0,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=500000,
                max_fee_per_gas=2000000000,
                max_priority_fee_per_gas=1000000000,
                calls=(Call.create(to=b"", value=0, data="0x6080604052"),),
            ),
        },
        id="contract_creation",
    ),
    # -------------------------------------------------------------------------
    # Complex combinations
    # -------------------------------------------------------------------------
    pytest.param(
        {
            "name": "full_featured_transaction",
            "legacy": lambda: create_tempo_transaction(
                to="",
                calls=[
                    {"to": ADDR_A, "value": 1000, "data": "0xabcd"},
                    {"to": ADDR_B, "value": 2000, "data": "0xef01"},
                ],
                gas=500000,
                max_fee_per_gas=5000000000,
                max_priority_fee_per_gas=2000000000,
                nonce=42,
                nonce_key=7,
                chain_id=42429,
                fee_token=FEE_TOKEN,
                valid_after=1700000000,
                valid_before=1800000000,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=500000,
                max_fee_per_gas=5000000000,
                max_priority_fee_per_gas=2000000000,
                nonce=42,
                nonce_key=7,
                fee_token=FEE_TOKEN,
                valid_after=1700000000,
                valid_before=1800000000,
                calls=(
                    Call.create(to=ADDR_A, value=1000, data="0xabcd"),
                    Call.create(to=ADDR_B, value=2000, data="0xef01"),
                ),
            ),
        },
        id="full_featured_transaction",
    ),
    pytest.param(
        {
            "name": "high_gas_values",
            "legacy": lambda: create_tempo_transaction(
                to=ADDR_A,
                value=10**18,  # 1 ETH
                gas=10000000,
                max_fee_per_gas=100000000000,  # 100 gwei
                max_priority_fee_per_gas=50000000000,  # 50 gwei
                nonce=999999,
                chain_id=42429,
            ),
            "typed": lambda: TempoTransaction.create(
                chain_id=42429,
                gas_limit=10000000,
                max_fee_per_gas=100000000000,
                max_priority_fee_per_gas=50000000000,
                nonce=999999,
                calls=(Call.create(to=ADDR_A, value=10**18),),
            ),
        },
        id="high_gas_values",
    ),
]


class TestEquivalence:
    """Test that legacy and typed APIs produce identical results."""

    @pytest.mark.parametrize("test_case", EQUIVALENCE_TEST_CASES)
    def test_signing_hash_matches(self, test_case):
        """Verify both APIs produce the same signing hash."""
        legacy_tx = test_case["legacy"]()
        typed_tx = test_case["typed"]()

        legacy_hash = legacy_tx.get_signing_hash()
        typed_hash = typed_tx.get_signing_hash()

        assert legacy_hash == typed_hash, (
            f"Signing hash mismatch for {test_case['name']}: "
            f"legacy={legacy_hash.hex()}, typed={typed_hash.hex()}"
        )

    @pytest.mark.parametrize("test_case", EQUIVALENCE_TEST_CASES)
    def test_encoded_transaction_matches(self, test_case):
        """Verify both APIs produce the same encoded transaction after signing."""
        legacy_tx = test_case["legacy"]()
        typed_tx = test_case["typed"]()

        # Sign both
        legacy_tx.sign(TEST_PRIVATE_KEY)
        signed_typed = typed_tx.sign(TEST_PRIVATE_KEY)

        legacy_encoded = legacy_tx.encode()
        typed_encoded = signed_typed.encode()

        assert legacy_encoded == typed_encoded, (
            f"Encoded transaction mismatch for {test_case['name']}: "
            f"legacy={legacy_encoded.hex()}, typed={typed_encoded.hex()}"
        )

    @pytest.mark.parametrize("test_case", EQUIVALENCE_TEST_CASES)
    def test_transaction_hash_matches(self, test_case):
        """Verify both APIs produce the same transaction hash after signing."""
        legacy_tx = test_case["legacy"]()
        typed_tx = test_case["typed"]()

        # Sign both
        legacy_tx.sign(TEST_PRIVATE_KEY)
        signed_typed = typed_tx.sign(TEST_PRIVATE_KEY)

        legacy_hash = legacy_tx.hash()
        typed_hash = signed_typed.hash()

        assert legacy_hash == typed_hash, (
            f"Transaction hash mismatch for {test_case['name']}: "
            f"legacy={legacy_hash.hex()}, typed={typed_hash.hex()}"
        )

    @pytest.mark.parametrize("test_case", EQUIVALENCE_TEST_CASES)
    def test_vrs_matches(self, test_case):
        """Verify both APIs produce the same v, r, s signature values."""
        legacy_tx = test_case["legacy"]()
        typed_tx = test_case["typed"]()

        # Sign both
        legacy_tx.sign(TEST_PRIVATE_KEY)
        signed_typed = typed_tx.sign(TEST_PRIVATE_KEY)

        legacy_vrs = legacy_tx.vrs()
        typed_vrs = signed_typed.vrs()

        assert legacy_vrs == typed_vrs, (
            f"VRS mismatch for {test_case['name']}: "
            f"legacy={legacy_vrs}, typed={typed_vrs}"
        )

    @pytest.mark.parametrize("test_case", EQUIVALENCE_TEST_CASES)
    def test_sender_address_matches(self, test_case):
        """Verify both APIs derive the same sender address after signing."""
        legacy_tx = test_case["legacy"]()
        typed_tx = test_case["typed"]()

        # Sign both
        legacy_tx.sign(TEST_PRIVATE_KEY)
        signed_typed = typed_tx.sign(TEST_PRIVATE_KEY)

        # Legacy stores as bytes, typed as Address (also bytes)
        assert legacy_tx.sender_address == bytes(signed_typed.sender_address), (
            f"Sender address mismatch for {test_case['name']}"
        )


class TestFromDictEquivalence:
    """Test that from_dict parsing matches legacy dict parsing."""

    DICT_TEST_CASES = [
        pytest.param(
            {
                "name": "camel_case_basic",
                "dict": {
                    "chainId": 42429,
                    "gas": 100000,
                    "maxFeePerGas": 2000000000,
                    "maxPriorityFeePerGas": 1000000000,
                    "nonce": 5,
                    "to": ADDR_A,
                    "value": 1000,
                },
            },
            id="camel_case_basic",
        ),
        pytest.param(
            {
                "name": "snake_case_basic",
                "dict": {
                    "chain_id": 42429,
                    "gas_limit": 100000,
                    "max_fee_per_gas": 2000000000,
                    "max_priority_fee_per_gas": 1000000000,
                    "nonce": 5,
                    "to": ADDR_A,
                    "value": 1000,
                },
            },
            id="snake_case_basic",
        ),
        pytest.param(
            {
                "name": "with_calls",
                "dict": {
                    "chainId": 42429,
                    "gas": 200000,
                    "maxFeePerGas": 2000000000,
                    "maxPriorityFeePerGas": 1000000000,
                    "nonce": 0,
                    "calls": [
                        {"to": ADDR_A, "value": 100, "data": "0xab"},
                        {"to": ADDR_B, "value": 200, "data": "0xcd"},
                    ],
                },
            },
            id="with_calls",
        ),
        pytest.param(
            {
                "name": "with_fee_token",
                "dict": {
                    "chainId": 42429,
                    "gas": 100000,
                    "maxFeePerGas": 2000000000,
                    "maxPriorityFeePerGas": 1000000000,
                    "nonce": 0,
                    "to": ADDR_A,
                    "value": 0,
                    "feeToken": FEE_TOKEN,
                },
            },
            id="with_fee_token",
        ),
        pytest.param(
            {
                "name": "with_nonce_key",
                "dict": {
                    "chainId": 42429,
                    "gas": 100000,
                    "maxFeePerGas": 2000000000,
                    "maxPriorityFeePerGas": 1000000000,
                    "nonce": 10,
                    "nonceKey": 5,
                    "to": ADDR_A,
                    "value": 0,
                },
            },
            id="with_nonce_key",
        ),
        pytest.param(
            {
                "name": "with_validity",
                "dict": {
                    "chainId": 42429,
                    "gas": 100000,
                    "maxFeePerGas": 2000000000,
                    "maxPriorityFeePerGas": 1000000000,
                    "nonce": 0,
                    "to": ADDR_A,
                    "value": 0,
                    "validAfter": 1700000000,
                    "validBefore": 1800000000,
                },
            },
            id="with_validity",
        ),
        pytest.param(
            {
                "name": "full_featured",
                "dict": {
                    "chainId": 42429,
                    "gas": 500000,
                    "maxFeePerGas": 5000000000,
                    "maxPriorityFeePerGas": 2000000000,
                    "nonce": 42,
                    "nonceKey": 7,
                    "feeToken": FEE_TOKEN,
                    "validAfter": 1700000000,
                    "validBefore": 1800000000,
                    "calls": [
                        {"to": ADDR_A, "value": 1000, "data": "0xabcd"},
                        {"to": ADDR_B, "value": 2000, "data": "0xef01"},
                    ],
                },
            },
            id="full_featured",
        ),
    ]

    @pytest.mark.parametrize("test_case", DICT_TEST_CASES)
    def test_from_dict_signing_hash_matches(self, test_case):
        """Verify from_dict produces same signing hash as legacy constructor."""
        from pytempo import LegacyTempoTransaction

        d = test_case["dict"]
        legacy_tx = LegacyTempoTransaction(d)
        typed_tx = TempoTransaction.from_dict(d)

        legacy_hash = legacy_tx.get_signing_hash()
        typed_hash = typed_tx.get_signing_hash()

        assert legacy_hash == typed_hash, (
            f"Signing hash mismatch for {test_case['name']}"
        )

    @pytest.mark.parametrize("test_case", DICT_TEST_CASES)
    def test_from_dict_encoded_matches(self, test_case):
        """Verify from_dict produces same encoded tx as legacy constructor."""
        from pytempo import LegacyTempoTransaction

        d = test_case["dict"]
        legacy_tx = LegacyTempoTransaction(d)
        typed_tx = TempoTransaction.from_dict(d)

        legacy_tx.sign(TEST_PRIVATE_KEY)
        signed_typed = typed_tx.sign(TEST_PRIVATE_KEY)

        assert legacy_tx.encode() == signed_typed.encode(), (
            f"Encoded transaction mismatch for {test_case['name']}"
        )
