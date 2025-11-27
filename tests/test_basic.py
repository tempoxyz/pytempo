"""Basic tests for pytempo."""

from pytempo import TempoAATransaction, create_tempo_transaction


def test_import():
    """Test that imports work."""
    assert TempoAATransaction is not None
    assert create_tempo_transaction is not None


def test_create_transaction():
    """Test creating a basic transaction."""
    tx = create_tempo_transaction(
        to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
        value=0,
        gas=100000,
        max_fee_per_gas=2000000000,
        max_priority_fee_per_gas=1000000000,
        nonce=0,
        chain_id=42429,
    )

    assert tx is not None
    assert tx.gas_limit == 100000
    assert tx.chain_id == 42429
    assert len(tx.calls) == 1


def test_transaction_signing():
    """Test signing a transaction."""
    tx = create_tempo_transaction(
        to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
        value=0,
        gas=100000,
        max_fee_per_gas=2000000000,
        max_priority_fee_per_gas=1000000000,
        nonce=0,
        chain_id=42429,
    )

    private_key = "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"
    tx.sign(private_key)

    assert tx.signature is not None
    assert tx.v is not None
    assert tx.r is not None
    assert tx.s is not None


def test_transaction_encoding():
    """Test encoding a signed transaction."""
    tx = create_tempo_transaction(
        to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
        value=0,
        gas=100000,
        max_fee_per_gas=2000000000,
        max_priority_fee_per_gas=1000000000,
        nonce=0,
        chain_id=42429,
    )

    private_key = "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"
    tx.sign(private_key)

    encoded = tx.encode()

    assert isinstance(encoded, bytes)
    assert encoded[0] == 0x76  # Transaction type
    assert len(encoded) > 1


def test_batch_calls():
    """Test creating transaction with multiple calls."""
    tx = create_tempo_transaction(
        to="",
        calls=[
            {
                "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                "value": 0,
                "data": "0x",
            },
            {
                "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                "value": 100,
                "data": "0xabcd",
            },
        ],
        gas=200000,
        max_fee_per_gas=2000000000,
        max_priority_fee_per_gas=1000000000,
        nonce=0,
        chain_id=42429,
    )

    assert len(tx.calls) == 2
    assert tx.calls[0].value == 0
    assert tx.calls[1].value == 100
