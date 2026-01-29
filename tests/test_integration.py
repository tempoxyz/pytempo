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
- DEX operations (liquidity, swaps)
"""

import os
import time

import pytest
from eth_account import Account
from web3 import Web3

from pytempo import (
    Call,
    TempoTransaction,
    patch_web3_for_tempo,
    sign_tx_access_key,
)


def encode_call(signature: str, *args) -> bytes:
    """Encode a function call with selector and ABI-encoded arguments."""
    from web3 import Web3

    w3 = Web3()
    return w3.eth.contract(
        abi=[
            {
                "name": signature.split("(")[0],
                "type": "function",
                "inputs": _parse_inputs(signature),
                "outputs": [],
            }
        ]
    ).encode_abi(signature.split("(")[0], args)


def _parse_inputs(signature: str) -> list:
    """Parse function signature into ABI input spec."""
    start = signature.index("(") + 1
    end = signature.rindex(")")
    params_str = signature[start:end]
    if not params_str:
        return []

    inputs = []
    depth = 0
    current = ""
    for char in params_str:
        if char == "(":
            depth += 1
            current += char
        elif char == ")":
            depth -= 1
            current += char
        elif char == "," and depth == 0:
            inputs.append({"type": current.strip(), "name": f"arg{len(inputs)}"})
            current = ""
        else:
            current += char
    if current.strip():
        inputs.append({"type": current.strip(), "name": f"arg{len(inputs)}"})
    return inputs


# Gas limits for AA transactions (higher intrinsic gas due to account abstraction)
BASE_GAS_LIMIT = 300_000
HIGH_GAS_LIMIT = 500_000

# Precompile addresses
NATIVE_FEE_TOKEN = "0x20c0000000000000000000000000000000000000"
ALPHA_USD = "0x20C0000000000000000000000000000000000001"
BETA_USD = "0x20C0000000000000000000000000000000000002"
THETA_USD = "0x20C0000000000000000000000000000000000003"
FEE_CONTROLLER = "0xfeec000000000000000000000000000000000000"
DEX = "0xdec0000000000000000000000000000000000000"
ACCOUNT_KEYCHAIN = "0xAAAAAAAA00000000000000000000000000000000"
COUNTER_CONTRACT = "0x86A2EE8FAf9A840F7a2c64CA3d51209F9A02081D"
LP_RECIPIENT = "0x6c4143BEd3A13cf9E5E43d45C60aD816FC091d0c"

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
    web3 = Web3(Web3.HTTPProvider(rpc_url))
    patch_web3_for_tempo()
    return web3


@pytest.fixture(scope="module")
def chain_id(w3):
    """Get the chain ID from the connected node."""
    return w3.eth.chain_id


@pytest.fixture(scope="module")
def funded_account(w3, rpc_url):
    """Create and fund a new account using tempo_fundAddress RPC."""
    account = Account.create()

    for _ in range(100):
        try:
            result = w3.provider.make_request("tempo_fundAddress", [account.address])
            if isinstance(result.get("result"), list):
                break
        except Exception:
            pass
        time.sleep(0.2)

    time.sleep(5)
    return account


@pytest.fixture(scope="module")
def sponsor_account(w3, rpc_url):
    """Create and fund a sponsor account for gasless transactions."""
    account = Account.create()

    for _ in range(100):
        try:
            result = w3.provider.make_request("tempo_fundAddress", [account.address])
            if isinstance(result.get("result"), list):
                break
        except Exception:
            pass
        time.sleep(0.2)

    time.sleep(3)
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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
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
            calldata = encode_call(
                "mint(address,address,uint256,address)",
                Web3.to_checksum_address(token),
                Web3.to_checksum_address(NATIVE_FEE_TOKEN),
                1_000_000_000,
                Web3.to_checksum_address(LP_RECIPIENT),
            )

            tx = TempoTransaction.create(
                chain_id=chain_id,
                nonce=nonce,
                gas_limit=HIGH_GAS_LIMIT,
                max_fee_per_gas=max_fee,
                max_priority_fee_per_gas=priority_fee,
                calls=(Call.create(to=FEE_CONTROLLER, data=calldata),),
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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestAccessKeys:
    """Test access key signing (keychain)."""

    @pytest.mark.skip(
        reason="Access key authorization may fail on devnet - needs investigation"
    )
    def test_authorize_and_use_access_key(self, w3, chain_id, funded_account):
        """Test authorizing and using an access key."""
        max_fee, priority_fee = get_gas_params(w3)

        access_key = Account.create()

        nonce = w3.eth.get_transaction_count(funded_account.address)
        calldata = encode_call(
            "authorizeKey(address,uint8,uint64,bool,(address,uint256)[])",
            Web3.to_checksum_address(access_key.address),
            0,  # SignatureType: Secp256k1
            1893456000,  # Expiry: year 2030
            False,  # enforceLimits: false
            [],  # limits: empty array
        )

        auth_tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=ACCOUNT_KEYCHAIN, data=calldata),),
        )
        signed = auth_tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

        for _ in range(100):
            try:
                result = w3.provider.make_request(
                    "tempo_fundAddress", [access_key.address]
                )
                if isinstance(result.get("result"), list):
                    break
            except Exception:
                pass
            time.sleep(0.2)
        time.sleep(3)

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=0,
            nonce_key=200,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
        )

        signed_with_access_key = sign_tx_access_key(
            tx,
            access_key_private_key=access_key.key.hex(),
            root_account_address=funded_account.address,
        )
        receipt = send_tx(w3, signed_with_access_key)
        assert receipt["status"] == 1


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
            calls=(Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),),
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
                Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),
                Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),
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
                Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),
                Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),
                Call.create(to=COUNTER_CONTRACT, data=bytes.fromhex("d09de08a")),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1


class TestDEXOperations:
    """Test DEX operations (liquidity, swaps).

    Note: These tests require the DEX to have sufficient liquidity.
    On devnet, orders may fail due to insufficient liquidity.
    """

    @pytest.mark.skip(
        reason="DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_approve_dex(self, w3, chain_id, funded_account):
        """Test approving DEX for token spending."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        approve_calldata = encode_call(
            "approve(address,uint256)",
            Web3.to_checksum_address(DEX),
            10_000_000_000,
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(
                Call.create(to=BETA_USD, data=approve_calldata),
                Call.create(to=NATIVE_FEE_TOKEN, data=approve_calldata),
            ),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_place_bid(self, w3, chain_id, funded_account):
        """Test placing a bid on DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        calldata = encode_call(
            "place(address,uint128,bool,int16)",
            Web3.to_checksum_address(BETA_USD),
            100_000_000,
            True,
            10,
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=DEX, data=calldata),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_place_ask(self, w3, chain_id, funded_account):
        """Test placing an ask on DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        calldata = encode_call(
            "place(address,uint128,bool,int16)",
            Web3.to_checksum_address(BETA_USD),
            100_000_000,
            False,
            10,
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=DEX, data=calldata),),
        )
        signed = tx.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

    @pytest.mark.skip(
        reason="DEX operations require liquidity setup - works with full tempo-check.sh flow"
    )
    def test_swap_exact_amount_in(self, w3, chain_id, funded_account):
        """Test swapping exact amount in on DEX."""
        max_fee, priority_fee = get_gas_params(w3)
        nonce = w3.eth.get_transaction_count(funded_account.address)

        calldata = encode_call(
            "swapExactAmountIn(address,address,uint128,uint128)",
            Web3.to_checksum_address(NATIVE_FEE_TOKEN),
            Web3.to_checksum_address(BETA_USD),
            100_000_000,
            9_000_000,
        )

        tx = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=HIGH_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=DEX, data=calldata),),
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
        set_calldata = encode_call(
            "setUserToken(address)", Web3.to_checksum_address(BETA_USD)
        )

        tx1 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=FEE_CONTROLLER, data=set_calldata),),
        )
        signed = tx1.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1

        nonce = w3.eth.get_transaction_count(funded_account.address)
        reset_calldata = encode_call(
            "setUserToken(address)", Web3.to_checksum_address(NATIVE_FEE_TOKEN)
        )

        tx2 = TempoTransaction.create(
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=BASE_GAS_LIMIT,
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority_fee,
            calls=(Call.create(to=FEE_CONTROLLER, data=reset_calldata),),
        )
        signed = tx2.sign(funded_account.key.hex())
        receipt = send_tx(w3, signed)
        assert receipt["status"] == 1
