"""Basic tests for pytempo."""

from pytempo import Call, TempoTransaction


def test_import():
    """Test that imports work."""
    assert TempoTransaction is not None
    assert Call is not None


def test_create_transaction():
    """Test creating a basic transaction."""
    tx = TempoTransaction.create(
        chain_id=42429,
        gas_limit=100_000,
        max_fee_per_gas=2_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        nonce=0,
        calls=(Call.create(to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=0),),
    )

    assert tx is not None
    assert tx.gas_limit == 100_000
    assert tx.chain_id == 42429
    assert len(tx.calls) == 1


def test_transaction_signing():
    """Test signing a transaction."""
    tx = TempoTransaction.create(
        chain_id=42429,
        gas_limit=100_000,
        max_fee_per_gas=2_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        nonce=0,
        calls=(Call.create(to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=0),),
    )

    private_key = "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"
    signed_tx = tx.sign(private_key)

    assert signed_tx.sender_signature is not None


def test_transaction_encoding():
    """Test encoding a signed transaction."""
    tx = TempoTransaction.create(
        chain_id=42429,
        gas_limit=100_000,
        max_fee_per_gas=2_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        nonce=0,
        calls=(Call.create(to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=0),),
    )

    private_key = "0x7eafbf9699b30c9ed8e3d6bbae57dd4f047544fde34d4c982dd591c2bee39ad0"
    signed_tx = tx.sign(private_key)
    encoded = signed_tx.encode()

    assert isinstance(encoded, bytes)
    assert encoded[0] == 0x76  # Transaction type
    assert len(encoded) > 1


def test_batch_calls():
    """Test creating transaction with multiple calls."""
    tx = TempoTransaction.create(
        chain_id=42429,
        gas_limit=200_000,
        max_fee_per_gas=2_000_000_000,
        max_priority_fee_per_gas=1_000_000_000,
        nonce=0,
        calls=(
            Call.create(to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55", value=0),
            Call.create(
                to="0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
                value=100,
                data="0xabcd",
            ),
        ),
    )

    assert len(tx.calls) == 2
    assert tx.calls[0].value == 0
    assert tx.calls[1].value == 100


def test_from_dict_coerces_hex_string_quantities():
    """JSON-RPC dicts hex-encode quantities; from_dict must accept them."""
    tx = TempoTransaction.from_dict(
        {
            "chainId": "0xa5bd",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x1",
            "gas": "0x186a0",
            "nonce": "0x5",
            "to": "0xF0109fC8DF283027b6285cc889F5aA624EaC1F55",
            "value": "0x64",
            "data": "0x",
        }
    )
    tx.validate()
    assert tx.chain_id == 0xA5BD
    assert tx.max_fee_per_gas == 0x77359400
    assert tx.max_priority_fee_per_gas == 1
    assert tx.gas_limit == 0x186A0
    assert tx.nonce == 5
    assert tx.calls[0].value == 100


def test_from_dict_accepts_int_quantities():
    """Snake_case/int dicts still parse (no regression)."""
    tx = TempoTransaction.from_dict(
        {"chain_id": 42429, "gas": 100_000, "value": 7, "to": "0x" + "a" * 40}
    )
    tx.validate()
    assert tx.chain_id == 42429
    assert tx.gas_limit == 100_000
    assert tx.calls[0].value == 7
