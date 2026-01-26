"""Tempo Transaction (Type 0x76) - Legacy mutable wrapper for backwards compatibility.

For new code, prefer using the strongly-typed immutable API:

    from pytempo import TempoTransaction

    tx = (TempoTransaction.create(chain_id=42429)
        .with_gas(100_000)
        .add_call("0xRecipient...", value=1000)
        .sign("0xPrivateKey..."))
"""

from typing import Optional

from eth_account import Account
from eth_utils import to_bytes

from .models import AccessListItem, Call, Signature
from .models import TempoTransaction as TypedTempoTransaction
from .types import Address, as_address

__all__ = [
    "LegacyTempoTransaction",
    "TempoAATransaction",
    "create_tempo_transaction",
    "patch_web3_for_tempo",
]


class LegacyTempoTransaction:
    """
    Tempo Transaction (Type 0x76) - Mutable wrapper for backwards compatibility.

    For new code, prefer using the immutable TempoTransaction:

        tx = (TempoTransaction.create(chain_id=42429)
            .add_call("0xRecipient...", value=1000)
            .with_gas(100_000)
            .sign("0xPrivateKey..."))
    """

    TRANSACTION_TYPE = 0x76
    FEE_PAYER_MAGIC_BYTE = 0x78

    def __init__(self, transaction_dict: Optional[dict] = None, **kwargs):
        if transaction_dict is not None:
            self._init_from_dict(transaction_dict)
        else:
            self._init_from_kwargs(kwargs)

    def _init_from_kwargs(self, kwargs: dict):
        """Initialize from keyword arguments."""
        self.chain_id = kwargs.get("chain_id", 1)
        self.max_priority_fee_per_gas = kwargs.get("max_priority_fee_per_gas", 0)
        self.max_fee_per_gas = kwargs.get("max_fee_per_gas", 0)
        self.gas_limit = kwargs.get("gas_limit", 21_000)
        self.calls = list(kwargs.get("calls", []))
        self.access_list = list(kwargs.get("access_list", []))
        self.nonce_key = kwargs.get("nonce_key", 0)
        self.nonce = kwargs.get("nonce", 0)
        self.valid_before = kwargs.get("valid_before")
        self.valid_after = kwargs.get("valid_after")
        self.fee_token = kwargs.get("fee_token")
        self.sender_address = kwargs.get("sender_address")
        self._will_have_fee_payer = kwargs.get("awaiting_fee_payer", False)
        self.fee_payer_signature = kwargs.get("fee_payer_signature")
        self.signature = kwargs.get("signature")
        self.v = kwargs.get("v")
        self.r = kwargs.get("r")
        self.s = kwargs.get("s")
        self.tempo_authorization_list = list(kwargs.get("tempo_authorization_list", []))

    def _init_from_dict(self, transaction_dict: dict):
        """Parse a transaction dict with support for both camelCase and snake_case keys."""

        def get_key(d: dict, *keys, default=None):
            for key in keys:
                if key in d:
                    return d[key]
            return default

        self.chain_id = get_key(transaction_dict, "chainId", "chain_id", default=1)
        self.max_priority_fee_per_gas = get_key(
            transaction_dict,
            "maxPriorityFeePerGas",
            "max_priority_fee_per_gas",
            default=0,
        )
        self.max_fee_per_gas = get_key(
            transaction_dict, "maxFeePerGas", "max_fee_per_gas", default=0
        )
        self.gas_limit = get_key(
            transaction_dict, "gas", "gasLimit", "gas_limit", default=21000
        )

        calls_data = get_key(transaction_dict, "calls", default=[])
        if not calls_data:
            to_addr = get_key(transaction_dict, "to", default="")
            value = get_key(transaction_dict, "value", default=0)
            data = get_key(transaction_dict, "data", "input", default="0x")
            if to_addr or value or (data and data != "0x"):
                calls_data = [{"to": to_addr, "value": value, "data": data}]

        self.calls = []
        for call in calls_data:
            to_val = call.get("to", "")
            data_val = call.get("data", call.get("input", "0x"))
            self.calls.append(
                Call.create(
                    to=to_val if to_val else b"",
                    value=call.get("value", 0),
                    data=data_val,
                )
            )

        access_list_data = get_key(
            transaction_dict, "accessList", "access_list", default=[]
        )
        self.access_list = []
        for item in access_list_data:
            storage_keys = tuple(item.get("storageKeys", item.get("storage_keys", [])))
            self.access_list.append(
                AccessListItem.create(
                    address=item["address"],
                    storage_keys=storage_keys,
                )
            )

        self.nonce_key = get_key(transaction_dict, "nonceKey", "nonce_key", default=0)
        self.nonce = get_key(transaction_dict, "nonce", default=0)
        self.valid_before = get_key(transaction_dict, "validBefore", "valid_before")
        self.valid_after = get_key(transaction_dict, "validAfter", "valid_after")

        fee_token_raw = get_key(transaction_dict, "feeToken", "fee_token")
        self.fee_token: Optional[Address] = None
        if fee_token_raw:
            self.fee_token = as_address(fee_token_raw)

        self.fee_payer_signature = get_key(
            transaction_dict, "feePayerSignature", "fee_payer_signature"
        )

        self.tempo_authorization_list = list(
            get_key(
                transaction_dict,
                "tempoAuthorizationList",
                "tempo_authorization_list",
                "aaAuthorizationList",
                "aa_authorization_list",
                default=[],
            )
        )

        self.signature = get_key(transaction_dict, "signature")
        self.v = get_key(transaction_dict, "v")
        self.r = get_key(transaction_dict, "r")
        self.s = get_key(transaction_dict, "s")
        self.sender_address = None
        self._will_have_fee_payer = bool(
            get_key(transaction_dict, "_will_have_fee_payer", default=False)
        )

    def validate(self) -> None:
        """Validate the transaction fields."""
        if self.chain_id <= 0:
            raise ValueError("chain_id must be > 0")
        if self.gas_limit <= 0:
            raise ValueError("gas_limit must be > 0")
        if self.max_priority_fee_per_gas < 0:
            raise ValueError("max_priority_fee_per_gas must be >= 0")
        if self.max_fee_per_gas < 0:
            raise ValueError("max_fee_per_gas must be >= 0")
        if (
            self.max_fee_per_gas
            and self.max_priority_fee_per_gas > self.max_fee_per_gas
        ):
            raise ValueError("max_priority_fee_per_gas cannot exceed max_fee_per_gas")
        if self.nonce < 0:
            raise ValueError("nonce must be >= 0")
        if self.nonce_key < 0:
            raise ValueError("nonce_key must be >= 0")
        if not self.calls:
            raise ValueError("at least one call is required")

    def _to_typed(self) -> TypedTempoTransaction:
        """Convert to immutable typed transaction."""
        sender_sig = None
        if (
            self.signature
            and isinstance(self.signature, bytes)
            and len(self.signature) == 65
        ):
            sender_sig = Signature.from_bytes(self.signature)
        elif self.v is not None and self.r is not None and self.s is not None:
            sender_sig = Signature(r=self.r, s=self.s, v=self.v)

        fee_payer_sig = None
        if (
            self.fee_payer_signature
            and isinstance(self.fee_payer_signature, bytes)
            and len(self.fee_payer_signature) == 65
        ):
            fee_payer_sig = Signature.from_bytes(self.fee_payer_signature)

        return TypedTempoTransaction(
            chain_id=self.chain_id,
            max_priority_fee_per_gas=self.max_priority_fee_per_gas,
            max_fee_per_gas=self.max_fee_per_gas,
            gas_limit=self.gas_limit,
            calls=tuple(self.calls),
            access_list=tuple(self.access_list),
            nonce_key=self.nonce_key,
            nonce=self.nonce,
            valid_before=self.valid_before,
            valid_after=self.valid_after,
            fee_token=self.fee_token,
            sender_address=as_address(self.sender_address)
            if self.sender_address
            else None,
            awaiting_fee_payer=self._will_have_fee_payer,
            fee_payer_signature=fee_payer_sig,
            sender_signature=sender_sig,
            tempo_authorization_list=tuple(self.tempo_authorization_list),
        )

    def get_signing_hash(self, for_fee_payer: bool = False) -> bytes:
        """Get the hash to sign."""
        return self._to_typed().get_signing_hash(for_fee_payer=for_fee_payer)

    def encode(self) -> bytes:
        """Encode complete transaction: 0x76 || rlp([14 fields])"""
        return self._to_typed().encode()

    def hash(self) -> bytes:
        """Get transaction hash."""
        return self._to_typed().hash()

    def vrs(self) -> tuple[Optional[int], Optional[int], Optional[int]]:
        """Get v, r, s values for secp256k1 signatures."""
        return (self.v, self.r, self.s)

    def sign(
        self, private_key: str, for_fee_payer: bool = False
    ) -> "LegacyTempoTransaction":
        """
        Sign the transaction with secp256k1 private key.

        Mutates the transaction in place for backwards compatibility.

        Args:
            private_key: Private key as hex string
            for_fee_payer: If True, sign as fee payer; else sign as sender
        """
        account = Account.from_key(private_key)

        if for_fee_payer:
            if not self.sender_address:
                raise ValueError("Must set sender_address before fee payer can sign")

            msg_hash = self.get_signing_hash(for_fee_payer=True)
            signed_msg = account.unsafe_sign_hash(msg_hash)
            self.fee_payer_signature = signed_msg.signature
        else:
            msg_hash = self.get_signing_hash(for_fee_payer=False)
            signed_msg = account.unsafe_sign_hash(msg_hash)

            self.signature = signed_msg.signature
            self.v = signed_msg.v
            self.r = signed_msg.r
            self.s = signed_msg.s
            self.sender_address = to_bytes(hexstr=account.address)

        return self


TempoAATransaction = LegacyTempoTransaction


def create_tempo_transaction(
    to: str,
    value: int = 0,
    data: str = "0x",
    gas: int = 21000,
    max_fee_per_gas: int = 0,
    max_priority_fee_per_gas: int = 0,
    nonce: int = 0,
    nonce_key: int = 0,
    chain_id: int = 1,
    fee_token: Optional[str] = None,
    calls: Optional[list[dict]] = None,
    valid_before: Optional[int] = None,
    valid_after: Optional[int] = None,
    **kwargs,
) -> LegacyTempoTransaction:
    """
    Create a Tempo transaction.

    Args:
        to: Destination address
        value: Value in wei
        data: Transaction data
        gas: Gas limit
        max_fee_per_gas: Max fee per gas
        max_priority_fee_per_gas: Max priority fee per gas
        nonce: Nonce value
        nonce_key: Nonce key for parallel nonces
        chain_id: Chain ID
        fee_token: Optional fee token address
        calls: Optional list of calls for batching
        valid_before: Optional expiration timestamp
        valid_after: Optional activation timestamp
        **kwargs: Additional optional fields

    Returns:
        LegacyTempoTransaction ready to sign
    """
    tx_dict = {
        "chainId": chain_id,
        "maxFeePerGas": max_fee_per_gas,
        "maxPriorityFeePerGas": max_priority_fee_per_gas,
        "gas": gas,
        "nonce": nonce,
        "nonceKey": nonce_key,
    }

    if valid_before is not None:
        tx_dict["validBefore"] = valid_before
    if valid_after is not None:
        tx_dict["validAfter"] = valid_after
    if fee_token:
        tx_dict["feeToken"] = fee_token

    if calls:
        tx_dict["calls"] = calls
    else:
        tx_dict["to"] = to
        tx_dict["value"] = value
        tx_dict["data"] = data

    tx_dict.update(kwargs)

    return LegacyTempoTransaction(tx_dict)


def patch_web3_for_tempo():
    """Monkey patch web3.py to support Tempo transactions (type 0x76).

    This patches TypedTransaction.from_dict to recognize type 0x76 transactions.
    Call this once at application startup before using web3.py with Tempo transactions.
    """
    from eth_account._utils.transaction_utils import set_transaction_type_if_needed
    from eth_account._utils.validation import is_int_or_prefixed_hexstr
    from eth_account.typed_transactions.typed_transaction import TypedTransaction
    from eth_utils.curried import hexstr_if_str, to_int
    from eth_utils.toolz import pipe

    original_from_dict = TypedTransaction.from_dict.__func__

    @classmethod
    def patched_from_dict(cls, dictionary, blobs=None):
        dictionary = set_transaction_type_if_needed(dictionary)

        if not ("type" in dictionary and is_int_or_prefixed_hexstr(dictionary["type"])):
            raise ValueError("missing or incorrect transaction type")

        transaction_type = pipe(dictionary["type"], hexstr_if_str(to_int))

        if transaction_type == 0x76:
            return LegacyTempoTransaction(dictionary)

        return original_from_dict(cls, dictionary, blobs)

    TypedTransaction.from_dict = patched_from_dict
