"""Tempo Transaction (Type 0x76) implementation with RLP encoding and web3.py integration."""

from dataclasses import dataclass
from typing import Optional

import rlp
from eth_account import Account
from eth_utils import keccak, to_bytes
from rlp.sedes import Binary, CountableList, big_endian_int, binary

address = Binary.fixed_length(20, allow_empty=True)
hash32 = Binary.fixed_length(32)
uint64 = big_endian_int
uint256 = big_endian_int
txi = big_endian_int


@dataclass
class Call:
    """Single call in a batch."""

    to: bytes
    value: int
    data: bytes

    def as_rlp_list(self):
        return [self.to, self.value, self.data]


class CallRLP(rlp.Serializable):
    fields = [
        ("to", binary),
        ("value", big_endian_int),
        ("data", binary),
    ]


class AccessListItemRLP(rlp.Serializable):
    fields = [
        ("address", address),
        ("storage_keys", CountableList(hash32)),
    ]


class TempoTransaction:
    """
    Tempo Transaction (Type 0x76).

    Features:
    - Four signature types: secp256k1, P256, WebAuthn, Keychain
    - 2D nonce system for parallel transactions
    - Gas sponsorship via fee payer
    - Call batching
    - Optional fee tokens
    - Transaction expiry windows
    - Access keys with spending limits
    """

    TRANSACTION_TYPE = 0x76
    FEE_PAYER_MAGIC_BYTE = 0x78

    def __init__(self, transaction_dict: dict):
        self.chain_id = transaction_dict.get(
            "chainId", transaction_dict.get("chain_id", 1)
        )
        self.max_priority_fee_per_gas = transaction_dict.get(
            "maxPriorityFeePerGas", transaction_dict.get("max_priority_fee_per_gas", 0)
        )
        self.max_fee_per_gas = transaction_dict.get(
            "maxFeePerGas", transaction_dict.get("max_fee_per_gas", 0)
        )
        self.gas_limit = transaction_dict.get(
            "gas", transaction_dict.get("gasLimit", 21000)
        )

        # Parse calls
        calls_data = transaction_dict.get("calls", [])
        if not calls_data:
            to_addr = transaction_dict.get("to", "")
            if to_addr:
                to_bytes_val = (
                    to_bytes(hexstr=to_addr) if isinstance(to_addr, str) else to_addr
                )
            else:
                to_bytes_val = b""

            value = transaction_dict.get("value", 0)
            data = transaction_dict.get("data", transaction_dict.get("input", "0x"))
            data_bytes = to_bytes(hexstr=data) if isinstance(data, str) else data

            calls_data = [{"to": to_bytes_val, "value": value, "data": data_bytes}]

        self.calls = []
        for call in calls_data:
            to_val = call.get("to", b"")
            if isinstance(to_val, str):
                to_val = to_bytes(hexstr=to_val) if to_val else b""

            data_val = call.get("data", call.get("input", b""))
            if isinstance(data_val, str):
                data_val = to_bytes(hexstr=data_val) if data_val else b""

            self.calls.append(
                Call(to=to_val, value=call.get("value", 0), data=data_val)
            )

        # Access list
        access_list = transaction_dict.get(
            "accessList", transaction_dict.get("access_list", [])
        )
        self.access_list = []
        for item in access_list:
            addr = (
                to_bytes(hexstr=item["address"])
                if isinstance(item["address"], str)
                else item["address"]
            )
            keys = [
                to_bytes(hexstr=k) if isinstance(k, str) else k
                for k in item.get("storageKeys", [])
            ]
            self.access_list.append({"address": addr, "storage_keys": keys})

        # 2D nonce system
        self.nonce_key = transaction_dict.get(
            "nonceKey", transaction_dict.get("nonce_key", 0)
        )
        self.nonce = transaction_dict.get("nonce", 0)

        # Optional expiry window
        self.valid_before = transaction_dict.get(
            "validBefore", transaction_dict.get("valid_before")
        )
        self.valid_after = transaction_dict.get(
            "validAfter", transaction_dict.get("valid_after")
        )

        # Fee token
        fee_token = transaction_dict.get("feeToken", transaction_dict.get("fee_token"))
        if fee_token:
            if isinstance(fee_token, str):
                self.fee_token = to_bytes(hexstr=fee_token)
            else:
                self.fee_token = fee_token
        else:
            self.fee_token = None

        # Fee payer signature (for sponsored transactions)
        self.fee_payer_signature = transaction_dict.get(
            "feePayerSignature", transaction_dict.get("fee_payer_signature")
        )

        # Tempo authorization list (EIP-7702 style delegation)
        self.tempo_authorization_list = transaction_dict.get(
            "tempoAuthorizationList",
            transaction_dict.get(
                "tempo_authorization_list",
                transaction_dict.get(
                    "aaAuthorizationList",
                    transaction_dict.get("aa_authorization_list", []),
                ),
            ),
        )

        # Sender signature
        self.signature = transaction_dict.get("signature")
        self.v = transaction_dict.get("v")
        self.r = transaction_dict.get("r")
        self.s = transaction_dict.get("s")

    def _encode_calls(self):
        return [[call.to, call.value, call.data] for call in self.calls]

    def _encode_access_list(self):
        return [[item["address"], item["storage_keys"]] for item in self.access_list]

    def get_signing_hash(self, for_fee_payer: bool = False) -> bytes:
        """
        Get the hash to sign.

        Args:
            for_fee_payer: If True, compute fee payer hash (0x78), else sender hash (0x76)

        Returns:
            32-byte hash to sign
        """
        if for_fee_payer:
            if not hasattr(self, "sender_address") or not self.sender_address:
                raise ValueError(
                    "Sender address must be set before computing fee payer hash"
                )

            fields = [
                self.chain_id,
                self.max_priority_fee_per_gas,
                self.max_fee_per_gas,
                self.gas_limit,
                self._encode_calls(),
                self._encode_access_list(),
                self.nonce_key,
                self.nonce,
                self.valid_before if self.valid_before is not None else b"",
                self.valid_after if self.valid_after is not None else b"",
                self.fee_token if self.fee_token is not None else b"",
                self.sender_address,
                self.tempo_authorization_list if self.tempo_authorization_list else [],
            ]

            encoded = rlp.encode(fields)
            return keccak(bytes([self.FEE_PAYER_MAGIC_BYTE]) + encoded)
        else:
            has_fee_payer = self.fee_payer_signature is not None or hasattr(
                self, "_will_have_fee_payer"
            )

            fields = [
                self.chain_id,
                self.max_priority_fee_per_gas,
                self.max_fee_per_gas,
                self.gas_limit,
                self._encode_calls(),
                self._encode_access_list(),
                self.nonce_key,
                self.nonce,
                self.valid_before if self.valid_before is not None else b"",
                self.valid_after if self.valid_after is not None else b"",
                b""
                if has_fee_payer
                else (self.fee_token if self.fee_token is not None else b""),
                bytes([0x00]) if has_fee_payer else b"",
                self.tempo_authorization_list if self.tempo_authorization_list else [],
            ]

            encoded = rlp.encode(fields)
            return keccak(bytes([self.TRANSACTION_TYPE]) + encoded)

    def encode(self) -> bytes:
        """
        Encode complete transaction: 0x76 || rlp([14 fields])

        Returns:
            Encoded transaction with type prefix
        """
        if self.signature:
            sender_sig = self.signature
        elif self.v is not None and self.r is not None and self.s is not None:
            sender_sig = (
                self.r.to_bytes(32, "big")
                + self.s.to_bytes(32, "big")
                + bytes([self.v])
            )
        else:
            sender_sig = b""

        fields = [
            self.chain_id,
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas,
            self.gas_limit,
            self._encode_calls(),
            self._encode_access_list(),
            self.nonce_key,
            self.nonce,
            self.valid_before if self.valid_before is not None else b"",
            self.valid_after if self.valid_after is not None else b"",
            self.fee_token if self.fee_token is not None else b"",
            self.fee_payer_signature if self.fee_payer_signature is not None else b"",
            self.tempo_authorization_list if self.tempo_authorization_list else [],
            sender_sig,
        ]

        encoded = rlp.encode(fields)
        return bytes([self.TRANSACTION_TYPE]) + encoded

    def hash(self) -> bytes:
        """Get transaction hash."""
        return keccak(self.encode())

    def vrs(self) -> tuple[int, int, int]:
        """Get v, r, s values for secp256k1 signatures."""
        if self.v is not None and self.r is not None and self.s is not None:
            return (self.v, self.r, self.s)

        if self.signature and len(self.signature) == 65:
            r = int.from_bytes(self.signature[:32], "big")
            s = int.from_bytes(self.signature[32:64], "big")
            v = self.signature[64]
            return (v, r, s)

        return (None, None, None)

    def sign(self, private_key: str, for_fee_payer: bool = False):
        """
        Sign the transaction with secp256k1 private key.

        Args:
            private_key: Private key as hex string or bytes
            for_fee_payer: If True, sign as fee payer; else sign as sender
        """
        account = Account.from_key(private_key)

        if for_fee_payer:
            if not hasattr(self, "sender_address") or not self.sender_address:
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


# Alias for backwards compatibility
TempoAATransaction = TempoTransaction


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
    **kwargs,
) -> TempoTransaction:
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
        **kwargs: Additional optional fields

    Returns:
        TempoTransaction ready to sign
    """
    tx_dict = {
        "to": to,
        "value": value,
        "data": data,
        "gas": gas,
        "maxFeePerGas": max_fee_per_gas,
        "maxPriorityFeePerGas": max_priority_fee_per_gas,
        "nonce": nonce,
        "nonceKey": nonce_key,
        "chainId": chain_id,
    }

    if fee_token:
        tx_dict["feeToken"] = fee_token

    if calls:
        tx_dict["calls"] = calls

    tx_dict.update(kwargs)

    return TempoTransaction(tx_dict)


# Backwards compatibility alias
TempoAATransaction = TempoTransaction


def patch_web3_for_tempo():
    """Monkey patch web3.py to support Tempo transactions (type 0x76)."""
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
            return TempoTransaction(dictionary)

        return original_from_dict(cls, dictionary, blobs)

    TypedTransaction.from_dict = patched_from_dict
