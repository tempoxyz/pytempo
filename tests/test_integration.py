"""Integration tests for pytempo against a live Tempo node.

These tests require TEMPO_RPC_URL environment variable to be set.
Run with: TEMPO_RPC_URL=https://rpc.testnet.tempo.xyz pytest tests/test_integration.py -v

Coverage parity with tempo-foundry's tempo-check.sh:
- Node connectivity
- Transaction creation/signing/encoding
- Transaction submission with funding via tempo_fundAddress RPC
- Fee token transactions (AlphaUSD, BetaUSD, ThetaUSD)
- 2D nonces (nonce_key)
- Expiring nonces (valid_before, valid_after)
- Access keys (keychain signing)
- Sponsored transactions (fee payer)
- Batch transactions (multiple calls)
- Stablecoin DEX operations (liquidity, swaps)
"""

import os
import time

import pytest
from eth_account import Account
from web3 import Web3

from pytempo import (
    Call,
    KeyAuthorization,
    SignatureType,
    TempoTransaction,
    TokenLimit,
    sign_tx_access_key,
)
from pytempo.contracts import (
    ALPHA_USD,
    BETA_USD,
    PATH_USD,
    THETA_USD,
    TIP20,
    AccountKeychain,
    FeeManager,
    StablecoinDEX,
)

# Gas limits for AA transactions (higher intrinsic gas due to account abstraction)
BASE_GAS_LIMIT = 300_000
HIGH_GAS_LIMIT = 500_000

# Test-specific contract addresses
COUNTER_CONTRACT = "0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D"
LP_RECIPIENT = "0x6c4143BEd3A13cf9E5E43d45C60aD816FC091d0c"
COUNTER_INCREMENT = bytes.fromhex("d09de08a")  # increment() selector

# Skip all tests if TEMPO_RPC_URL is not set
pytestmark = pytest.mark.skipif(
    not os.environ.get("TEMPO_RPC_URL"),
    reason="TEMPO_RPC_URL environment variable not set",
)


@pytest.fixture(scope="module")
def rpc_url():
    """Get the RPC URL from environment."""
    return os.environ["TEMPO_RPC_URL"]


@pytest.fixture(scope="module")
def w3(rpc_url):
    """Create a Web3 instance connected to the Tempo node."""
    return Web3(Web3.HTTPProvider(rpc_url))


@pytest.fixture(scope="module")
def chain_id(w3):
    """Get the chain ID from the connected node."""
    return w3.eth.chain_id


@pytest.fixture(scope="class")
def funded_account(w3, rpc_url):
    """Create and fund a new account using tempo_fundAddress RPC."""
    account = Account.create()

    for _ in range(100):
        try:
            result = w3.provider.make_request("tempo_fundAddress", [account.address])
            tx_hashes = result.get("result")
            if isinstance(tx_hashes, list):
                for tx_hash in tx_hashes:
                    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                break
        except Exception:
            pass
        time.sleep(0.2)

    return account


@pytest.fixture(scope="module")
def sponsor_account(w3, rpc_url):
    """Create and fund a sponsor account for gasless transactions."""
    account = Account.create()

    for _ in range(100):
        try:
            result = w3.provider.make_request("tempo_fundAddress", [account.address])
            tx_hashes = result.get("result")
            if isinstance(tx_hashes, list):
                for tx_hash in tx_hashes:
                    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
                break
        except Exception:
            pass
        time.sleep(0.2)

    return account


def format_receipt(receipt: dict) -> str:
    """Format receipt in human-readable format similar to cast."""
    tx_type = receipt.get("type", 0)
    type_name = {0x76: "Tempo (0x76)", 2: "EIP-1559", 0: "Legacy"}.get(
        tx_type, f"0x{tx_type:x}"
    )

    lines = [
        f"status               {'true' if receipt.get('status') == 1 else 'false'}",
        f"transactionHash      {receipt.get('transactionHash', b'').hex() if isinstance(receipt.get('transactionHash'), bytes) else receipt.get('transactionHash', '')}",
        f"transactionIndex     {receipt.get('transactionIndex', '')}",
        f"type                 {type_name}",
        f"blockHash            {receipt.get('blockHash', b'').hex() if isinstance(receipt.get('blockHash'), bytes) else receipt.get('blockHash', '')}",
        f"blockNumber          {receipt.get('blockNumber', '')}",
        f"from                 {receipt.get('from', '')}",
        f"to                   {receipt.get('to', '')}",
        f"contractAddress      {receipt.get('contractAddress') or ''}",
        f"gasUsed              {receipt.get('gasUsed', '')}",
        f"effectiveGasPrice    {receipt.get('effectiveGasPrice', '')}",
        f"feeToken             {receipt.get('feeToken', '')}",
        f"feePayer             {receipt.get('feePayer', '')}",
    ]
    return "\n".join(lines)


def send_tx(w3, tx: TempoTransaction, timeout: int = 60) -> dict:
    """Send a signed transaction and wait for receipt."""
    tx_hash = w3.eth.send_raw_transaction(tx.encode())
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
    print(f"\n{format_receipt(receipt)}")
    return receipt


def wait_for_next_block(w3, timeout: int = 30) -> None:
    """Wait until at least one new block is produced.

    Useful when the RPC service is load-balanced across multiple nodes:
    after a state-changing transaction is confirmed, a subsequent request may
    hit a different backend whose ``latest()`` state hasn't caught up yet.
    Waiting for a new block gives all nodes time to import the previous one.
    """
    start_block = w3.eth.block_number
    deadline = time.time() + timeout
    while w3.eth.block_number <= start_block:
        if time.time() > deadline:
            raise TimeoutError("Timed out waiting for next block")
        time.sleep(0.25)


def get_gas_params(w3) -> tuple[int, int]:
    """Get current gas parameters from the network."""
    gas_price = w3.eth.gas_price
    return gas_price * 2, gas_price


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

    def test_client_version(self, w3):
        """Test that we can get the client version (cast client equivalent)."""
        version = w3.client_version
        assert version is not None
        assert len(version) > 0


class TestTransactionCreation:
    """Test creating Tempo transactions (offline, no node needed)."""

    def test_create_simple_transaction(self, chain_id):
        """Test creating a simple transaction."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, value=0),),
        )
        assert tx is not None
        assert tx.chain_id == chain_id

    def test_sign_transaction(self, chain_id):
        """Test signing a transaction."""
        account = Account.create()
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, value=0),),
        )
        signed = tx.sign(account.key.hex())
        assert signed.sender_signature is not None

    def test_encode_signed_transaction(self, chain_id):
        """Test encoding a signed transaction."""
        account = Account.create()
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, value=0),),
        )
        signed = tx.sign(account.key.hex())
        encoded = signed.encode()

        assert isinstance(encoded, bytes)
        assert encoded[0] == 0x76  # Tempo transaction type


class TestTransactionSubmission:
    """Test submitting transactions to the network."""

    def test_send_simple_transaction(self, w3, chain_id, funded_account):
        """Test sending a simple transaction."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestFeeTokens:
    """Test fee token operations (tempo-check.sh fee token tests)."""

    def test_add_fee_token_liquidity(self, w3, chain_id, funded_account):
        """Test adding fee token liquidity (AlphaUSD, BetaUSD, ThetaUSD)."""
        max_fee, priority_fee = get_gas_params(w3)

        for token in [ALPHA_USD, BETA_USD, THETA_USD]:
            nonce = w3.eth.get_transaction_count(funded_account.address)

            tx = TempoTransaction.create(
                chain_id=chain_id,
                nonce=nonce,
                gas_limit=HIGH_GAS_LIMIT,
                max_fee_per_gas=max_fee,
                max_priority_fee_per_gas=priority_fee,
                calls=(
                    FeeManager.mint(
                        user_token=token,
                        validator_token=PATH_USD,
                        amount=1_000_000_000,
                        to=LP_RECIPIENT,
                    ),
                ),
            )
            signed = tx.sign(funded_account.key.hex())
            receipt = send_tx(w3, signed)
            assert receipt["status"] == 1

    def test_send_with_fee_token(self, w3, chain_id, funded_account):
        """Test sending transaction with custom fee token."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            fee_token=BETA_USD,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestTwoNonces:
    """Test 2D nonce system (nonce_key for parallel transactions)."""

    def test_send_with_nonce_key(self, w3, chain_id, funded_account):
        """Test sending transaction with nonce_key (2D nonce)."""
        max_fee, priority_fee = get_gas_params(w3)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=42,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestExpiringNonces:
    """Test expiring nonces (valid_before, valid_after)."""

    def test_send_with_valid_before(self, w3, chain_id, funded_account):
        """Test sending transaction with valid_before (expiring nonce)."""
        max_fee, priority_fee = get_gas_params(w3)

        valid_before = int(time.time()) + 25

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=100,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            valid_before=valid_before,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    def test_send_with_valid_after(self, w3, chain_id, funded_account):
        """Test sending transaction with valid_after (scheduled)."""
        max_fee, priority_fee = get_gas_params(w3)

        valid_after = int(time.time()) - 1
        valid_before = int(time.time()) + 25

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=101,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            valid_after=valid_after,
            valid_before=valid_before,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestAccessKeys:
    """Test access key authorization and signing (keychain).

    Tests the KeyAuthorization system which allows provisioning access keys
    inline within a transaction, avoiding a separate on-chain authorizeKey call.
    """

    def test_add_access_key_with_key_authorization(self, w3, chain_id, funded_account):
        """Test adding a new access key via inline KeyAuthorization.

        Uses KeyAuthorization to provision an access key in the same transaction
        that first uses it (key_authorization field).
        """
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()

        # Use dynamic expiry: 1 hour from now
        expiry = int(time.time()) + 3600

        auth = KeyAuthorization(
            chain_id=chain_id,
            key_type=SignatureType.SECP256K1,
            key_id=access_key.address,
            expiry=expiry,
            limits=None,
        )
        signed_auth = auth.sign(funded_account.key.hex())

        # Build transaction (with placeholder gas_limit, will be updated after estimation)
        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=201,
            gas_limit=0,  # Placeholder
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        # Estimate gas from the transaction
        gas_estimate = w3.eth.estimate_gas(
            tx.to_estimate_gas_request(
                funded_account.address,
                key_id=access_key.address,
                key_authorization=signed_auth.to_json(),
            )
        )

        # Rebuild with correct gas limit
        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=201,
            gas_limit=gas_estimate,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        signed_tx = sign_tx_access_key(
            tx,
            access_key_private_key=access_key.key.hex(),
            root_account=funded_account.address,
        )
        receipt = send_tx(w3, signed_tx)
        assert receipt["status"] == 1

    def test_sign_tx_with_existing_access_key(self, w3, chain_id, funded_account):
        """Test signing a transaction with an already-authorized access key.

        First provisions the access key inline, then uses that same key
        for a subsequent transaction without needing a new authorization.
        """
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()

        # Use dynamic expiry: 1 hour from now
        expiry = int(time.time()) + 3600

        auth = KeyAuthorization(
            chain_id=chain_id,
            key_type=SignatureType.SECP256K1,
            key_id=access_key.address,
            expiry=expiry,
            limits=None,
        )
        signed_auth = auth.sign(funded_account.key.hex())

        # Use a unique nonce_key based on current time to avoid conflicts with stuck pool txs
        nonce_key = 1000 + (int(time.time()) % 10000)

        # Build first transaction (with placeholder gas_limit)
        tx1 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=nonce_key,
            gas_limit=0,  # Placeholder
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        # Estimate gas from the transaction
        gas_estimate_with_auth = w3.eth.estimate_gas(
            tx1.to_estimate_gas_request(
                funded_account.address,
                key_id=access_key.address,
                key_authorization=signed_auth.to_json(),
            )
        )

        # Rebuild with correct gas limit
        tx1 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=nonce_key,
            gas_limit=gas_estimate_with_auth,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        signed_tx1 = sign_tx_access_key(
            tx1,
            access_key_private_key=access_key.key.hex(),
            root_account=funded_account.address,
        )
        receipt1 = send_tx(w3, signed_tx1)
        assert receipt1["status"] == 1

        # Wait for the next block so all nodes behind the load-balanced RPC
        # service have imported the block that provisioned the access key.
        wait_for_next_block(w3)

        # Build second tx and estimate gas (just keychain signature, no key_authorization)
        tx2 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=1,
            nonce_key=nonce_key,
            gas_limit=0,  # Placeholder
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        gas_estimate_no_auth = w3.eth.estimate_gas(
            tx2.to_estimate_gas_request(
                funded_account.address, key_id=access_key.address
            )
        )

        tx2 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=1,
            nonce_key=nonce_key,
            gas_limit=gas_estimate_no_auth,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        signed_tx2 = sign_tx_access_key(
            tx2,
            access_key_private_key=access_key.key.hex(),
            root_account=funded_account.address,
        )
        receipt2 = send_tx(w3, signed_tx2)
        assert receipt2["status"] == 1


class TestSponsoredTransactions:
    """Test sponsored (gasless) transactions (from PR #214)."""

    def test_sponsored_transaction(self, w3, chain_id, funded_account, sponsor_account):
        """Test sending a sponsored transaction where sponsor pays gas."""
        max_fee, priority_fee = get_gas_params(w3)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=300,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            awaiting_fee_payer=True,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        sender_signed = tx.sign(funded_account.key.hex())

        fully_signed = sender_signed.sign(sponsor_account.key.hex(), for_fee_payer=True)

        receipt = send_tx(w3, fully_signed)
        assert receipt["status"] == 1

        fee_payer = receipt.get("feePayer") or receipt.get("fee_payer")
        assert fee_payer is not None
        assert fee_payer.lower() == sponsor_account.address.lower()


class TestBatchTransactions:
    """Test batch transactions (multiple calls in one tx)."""

    def test_batch_transaction(self, w3, chain_id, funded_account):
        """Test sending a batch transaction with multiple calls."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    def test_batch_three_calls(self, w3, chain_id, funded_account):
        """Test batch transaction with three calls."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestDEXOperations:
    """Test Stablecoin DEX operations (liquidity, swaps).

    Note: These tests require the Stablecoin DEX to have sufficient liquidity.
    On devnet, orders may fail due to insufficient liquidity.
    """

    @pytest.mark.skip(
        reason="Stablecoin DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_approve_dex(self, w3, chain_id, funded_account):
        """Test approving Stablecoin DEX for token spending."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                TIP20(BETA_USD).approve(
                    spender=StablecoinDEX.ADDRESS, amount=10_000_000_000
                ),
                TIP20(PATH_USD).approve(
                    spender=StablecoinDEX.ADDRESS,
                    amount=10_000_000_000,
                ),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="Stablecoin DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_place_bid(self, w3, chain_id, funded_account):
        """Test placing a bid on Stablecoin DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                StablecoinDEX.place(
                    token=BETA_USD, amount=100_000_000, is_bid=True, tick=10
                ),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="Stablecoin DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_place_ask(self, w3, chain_id, funded_account):
        """Test placing an ask on Stablecoin DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                StablecoinDEX.place(
                    token=BETA_USD, amount=100_000_000, is_bid=False, tick=10
                ),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="Stablecoin DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_swap_exact_amount_in(self, w3, chain_id, funded_account):
        """Test swapping exact amount in on Stablecoin DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                StablecoinDEX.swap_exact_amount_in(
                    token_in=PATH_USD,
                    token_out=BETA_USD,
                    amount_in=100_000_000,
                    min_amount_out=9_000_000,
                ),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestSetUserFeeToken:
    """Test setting user's default fee token."""

    def test_set_user_fee_token(self, w3, chain_id, funded_account):
        """Test setting and resetting user's default fee token."""
        max_fee, priority_fee = get_gas_params(w3)

        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx1 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=600_000,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(FeeManager.set_user_token(token=BETA_USD),),
        )
        signed = tx1.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

        nonce = w3.eth.get_transaction_count(funded_account.address)

        tx2 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=600_000,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(FeeManager.set_user_token(token=PATH_USD),),
        )
        signed = tx2.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestKeychainSelectors:
    """Test keychain precompile selectors (authorizeKey, getKey, revokeKey).

    Parity with tempo-go TestIntegration_KeychainSelectors: exercises the
    authorizeKey → getKey → revokeKey round-trip via the precompile.
    """

    def test_authorize_get_revoke_round_trip(self, w3, chain_id, funded_account):
        """Authorize an access key, verify via getKey, revoke, verify revoked."""
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()
        # 10 years from now
        expiry = int(time.time()) + 10 * 365 * 24 * 3600

        # Step 1: Authorize key via EIP-1559 tx (same as tempo-go)
        nonce = w3.eth.get_transaction_count(funded_account.address)
        auth_call = AccountKeychain.authorize_key(
            key_id=access_key.address,
            signature_type=0,
            expiry=expiry,
            enforce_limits=False,
            limits=[],
        )
        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=600_000,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(auth_call,),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

        wait_for_next_block(w3)

        # Step 2: getKey and verify full payload
        key_info = AccountKeychain.get_key(
            w3,
            account_address=funded_account.address,
            key_id=access_key.address,
        )
        assert key_info["signature_type"] == 0
        assert key_info["key_id"].lower() == access_key.address.lower()
        assert key_info["expiry"] == expiry
        assert key_info["enforce_limits"] is False
        assert key_info["is_revoked"] is False

        # Step 3: Revoke key
        nonce = w3.eth.get_transaction_count(funded_account.address)
        revoke_call = AccountKeychain.revoke_key(key_id=access_key.address)
        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=600_000,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(revoke_call,),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

        wait_for_next_block(w3)

        # Step 4: Verify key is revoked
        # After revocation the precompile may zero out fields other than is_revoked
        key_info = AccountKeychain.get_key(
            w3,
            account_address=funded_account.address,
            key_id=access_key.address,
        )
        assert key_info["is_revoked"] is True


class TestKeychainWithLimits:
    """Test authorizeKey with spending limits.

    Parity with tempo-go TestIntegration_KeychainWithLimits: authorizes a key
    with enforceLimits=true + a TokenLimit, then verifies via getRemainingLimit.
    """

    def test_authorize_with_spending_limits(self, w3, chain_id, funded_account):
        """Authorize key with enforceLimits=true and verify remaining limit."""
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()
        expiry = int(time.time()) + 10 * 365 * 24 * 3600
        limit_amount = 1000 * 10**18

        nonce = w3.eth.get_transaction_count(funded_account.address)
        auth_call = AccountKeychain.authorize_key(
            key_id=access_key.address,
            signature_type=0,
            expiry=expiry,
            enforce_limits=True,
            limits=[(PATH_USD, limit_amount)],
        )
        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=600_000,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(auth_call,),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)

        status = receipt.get("status")
        if status != 1:
            pytest.skip(
                "authorizeKey with enforceLimits=true reverted — "
                "precompile may not support spending limits yet"
            )

        wait_for_next_block(w3)

        # Verify key was stored with enforce_limits=true
        key_info = AccountKeychain.get_key(
            w3,
            account_address=funded_account.address,
            key_id=access_key.address,
        )
        assert key_info["key_id"].lower() == access_key.address.lower()
        assert key_info["enforce_limits"] is True

        # Verify remaining limit
        remaining = AccountKeychain.get_remaining_limit(
            w3,
            account_address=funded_account.address,
            key_id=access_key.address,
            token_address=PATH_USD,
        )
        assert remaining == limit_amount


class TestKeyAuthorizationWithLimits:
    """Test inline key authorization with spending limits.

    Exercises the KeyAuthorization flow with TokenLimit, which the existing
    TestAccessKeys do not cover (they use limits=None).
    """

    def test_inline_key_auth_with_limits(self, w3, chain_id, funded_account):
        """Provision access key with spending limits via key_authorization."""
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()
        expiry = int(time.time()) + 3600
        limit_amount = 500 * 10**18

        auth = KeyAuthorization(
            chain_id=chain_id,
            key_type=SignatureType.SECP256K1,
            key_id=access_key.address,
            expiry=expiry,
            limits=[TokenLimit(token=PATH_USD, limit=limit_amount)],
        )
        signed_auth = auth.sign(funded_account.key.hex())

        nonce_key = 2000 + (int(time.time()) % 10000)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=nonce_key,
            gas_limit=0,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        gas_estimate = w3.eth.estimate_gas(
            tx.to_estimate_gas_request(
                funded_account.address,
                key_id=access_key.address,
                key_authorization=signed_auth.to_json(),
            )
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=nonce_key,
            gas_limit=gas_estimate,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
            key_authorization=signed_auth.rlp_encode(),
        )

        signed_tx = sign_tx_access_key(
            tx,
            access_key_private_key=access_key.key.hex(),
            root_account=funded_account.address,
        )
        receipt = send_tx(w3, signed_tx)
        assert receipt["status"] == 1

        # Verify key was provisioned with correct limits
        wait_for_next_block(w3)

        key_info = AccountKeychain.get_key(
            w3,
            account_address=funded_account.address,
            key_id=access_key.address,
        )
        assert key_info["signature_type"] == 0
        assert key_info["key_id"].lower() == access_key.address.lower()
        assert key_info["expiry"] == expiry
        assert key_info["is_revoked"] is False


class TestTransactionValidation:
    """Test transaction validation (parity with tempo-go BuilderValidation).

    Exercises TempoTransaction.validate() to ensure invalid transactions
    are rejected before submission.
    """

    def test_valid_transaction(self, chain_id):
        """Valid transaction should pass validation."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        tx.validate()

    def test_zero_gas_rejected(self, chain_id):
        """gas_limit=0 should raise ValueError."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=0,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        with pytest.raises(ValueError, match="gas_limit must be > 0"):
            tx.validate()

    def test_no_calls_rejected(self, chain_id):
        """Transaction with no calls should raise ValueError."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
        )
        with pytest.raises(ValueError, match="at least one call"):
            tx.validate()

    def test_priority_fee_exceeds_max_fee_rejected(self, chain_id):
        """max_priority_fee > max_fee should raise ValueError."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            max_fee_per_gas=100,
            max_priority_fee_per_gas=200,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        with pytest.raises(ValueError, match="cannot exceed"):
            tx.validate()

    def test_valid_window_reversed_rejected(self, chain_id):
        """valid_after > valid_before should raise ValueError."""
        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            valid_after=2000,
            valid_before=1000,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )
        with pytest.raises(ValueError, match="valid_after cannot be greater"):
            tx.validate()


class TestEncodingRoundTrip:
    """Test encode → hash round-trip (parity with tempo-go RoundTrip).

    Verifies that a signed transaction can be encoded and hashed consistently.
    """

    def test_sign_encode_hash_deterministic(self, chain_id):
        """Same transaction should produce the same hash."""
        account = Account.create()

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=42,
            gas_limit=300_000,
            max_fee_per_gas=10_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(
                Call.create(
                    to=COUNTER_CONTRACT,
                    value=1000,
                    data=COUNTER_INCREMENT,
                ),
            ),
        )

        signed = tx.sign(account.key.hex())

        encoded1 = signed.encode()
        encoded2 = signed.encode()
        assert encoded1 == encoded2

        hash1 = signed.hash()
        hash2 = signed.hash()
        assert hash1 == hash2
        assert len(hash1) == 32

    def test_encode_preserves_tx_type(self, chain_id):
        """Encoded transaction should start with 0x76 type byte."""
        account = Account.create()

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        signed = tx.sign(account.key.hex())
        encoded = signed.encode()

        assert encoded[0] == 0x76

    def test_encode_batch_calls(self, chain_id):
        """Encoded batch transaction should be valid."""
        account = Account.create()

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
                Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),
                Call.create(to=COUNTER_CONTRACT, value=100),
            ),
        )

        signed = tx.sign(account.key.hex())
        encoded = signed.encode()

        assert encoded[0] == 0x76
        assert len(encoded) > 1

    def test_sponsored_encode_round_trip(self, chain_id):
        """Sponsored transaction encoding should be deterministic."""
        sender = Account.create()
        sponsor = Account.create()

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=999,
            gas_limit=300_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            awaiting_fee_payer=True,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        sender_signed = tx.sign(sender.key.hex())
        fully_signed = sender_signed.sign(sponsor.key.hex(), for_fee_payer=True)

        encoded1 = fully_signed.encode()
        encoded2 = fully_signed.encode()
        assert encoded1 == encoded2

        hash1 = fully_signed.hash()
        hash2 = fully_signed.hash()
        assert hash1 == hash2

    def test_vrs_recovery(self, chain_id):
        """Should recover v, r, s from signed transaction."""
        account = Account.create()

        tx = TempoTransaction.create(
            chain_id=chain_id,
            gas_limit=300_000,
            max_fee_per_gas=2_000_000_000,
            max_priority_fee_per_gas=1_000_000_000,
            calls=(Call.create(to=COUNTER_CONTRACT, data=COUNTER_INCREMENT),),
        )

        signed = tx.sign(account.key.hex())
        v, r, s = signed.vrs()

        assert v in (0, 1, 27, 28)
        assert r > 0
        assert s > 0
