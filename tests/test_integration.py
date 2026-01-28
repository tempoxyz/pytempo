"""Integration tests for pytempo against a live Tempo node.

These tests require TEMPO_RPC_URL environment variable to be set.
Run with: TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz pytest tests/test_integration.py -v
"""

import os

import pytest
from web3 import Web3

from pytempo import Call, TempoTransaction, patch_web3_for_tempo

# Test accounts (Anvil/Hardhat defaults - only use on devnets)
TEST_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
TEST_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

RECIPIENT_PRIVATE_KEY = (
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
RECIPIENT_ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# Skip all tests if TEMPO_RPC_URL is not set
pytestmark = pytest.mark.skipif(
    not os.environ.get("TEMPO_RPC_URL"),
    reason="TEMPO_RPC_URL environment variable not set",
)


@pytest.fixture
def rpc_url():
    """Get the RPC URL from environment."""
    return os.environ["TEMPO_RPC_URL"]


@pytest.fixture
def w3(rpc_url):
    """Create a Web3 instance connected to the Tempo node."""
    web3 = Web3(Web3.HTTPProvider(rpc_url))
    patch_web3_for_tempo()
    return web3


@pytest.fixture
def chain_id(w3):
    """Get the chain ID from the connected node."""
    return w3.eth.chain_id


class TestNodeConnection:
    """Test basic node connectivity."""

    def test_node_is_reachable(self, w3):
        """Test that the node is reachable."""
        assert w3.is_connected()

    def test_get_block_number(self, w3):
        """Test that we can get the current block number."""
        block_number = w3.eth.block_number
        assert block_number >= 0

    def test_get_chain_id(self, w3, chain_id):
        """Test that we can get the chain ID."""
        assert chain_id > 0


class TestTransactionCreation:
    """Test creating Tempo transactions."""

    def test_create_simple_transaction(self, chain_id):
        """Test creating a simple transaction."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=100_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=RECIPIENT_ADDRESS, value=0),),
        )
        assert tx is not None
        assert tx.chain_id == chain_id

    def test_sign_transaction(self, chain_id):
        """Test signing a transaction."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=100_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=RECIPIENT_ADDRESS, value=0),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        assert signed.sender_signature is not None

    def test_encode_signed_transaction(self, chain_id):
        """Test encoding a signed transaction."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=100_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=RECIPIENT_ADDRESS, value=0),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        encoded = signed.encode()

        assert isinstance(encoded, bytes)
        assert encoded[0] == 0x76  # Tempo transaction type


class TestTransactionSubmission:
    """Test submitting transactions to the network.

    Note: These tests require funded test accounts on the target network.
    They may fail on devnet/testnet if accounts are not funded.
    """

    @pytest.mark.skip(reason="Requires funded test account")
    def test_send_simple_transaction(self, w3, chain_id):
        """Test sending a simple transaction."""
        nonce = w3.eth.get_transaction_count(TEST_ADDRESS)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=100_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=RECIPIENT_ADDRESS, value=0),),
        )
        signed = tx.sign(TEST_PRIVATE_KEY)
        encoded = signed.encode()

        tx_hash = w3.eth.send_raw_transaction(encoded)
        assert tx_hash is not None

        # Wait for receipt
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        assert receipt["status"] == 1
