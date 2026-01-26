"""Builder pattern for constructing Tempo transactions."""

from dataclasses import dataclass, field
from typing import Optional

from .models import AccessListItem, Call, TempoTransaction
from .types import Address, BytesLike, as_address


@dataclass
class TempoTransactionBuilder:
    """
    Fluent builder for constructing Tempo transactions.

    Example:
        tx = (TempoTransactionBuilder(chain_id=42429)
            .set_gas(100_000)
            .set_max_fee_per_gas(2_000_000_000)
            .add_call("0xRecipient...", value=1000)
            .build())
    """

    chain_id: int = 1
    max_priority_fee_per_gas: int = 0
    max_fee_per_gas: int = 0
    gas_limit: int = 21_000
    nonce: int = 0
    nonce_key: int = 0
    valid_before: Optional[int] = None
    valid_after: Optional[int] = None
    fee_token: Optional[Address] = None
    awaiting_fee_payer: bool = False
    tempo_authorization_list: list[bytes] = field(default_factory=list)
    access_list: list[AccessListItem] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)

    def set_gas(self, gas_limit: int) -> "TempoTransactionBuilder":
        """Set the gas limit."""
        self.gas_limit = gas_limit
        return self

    def set_max_fee_per_gas(self, max_fee: int) -> "TempoTransactionBuilder":
        """Set the maximum fee per gas."""
        self.max_fee_per_gas = max_fee
        return self

    def set_max_priority_fee_per_gas(
        self, priority_fee: int
    ) -> "TempoTransactionBuilder":
        """Set the maximum priority fee per gas."""
        self.max_priority_fee_per_gas = priority_fee
        return self

    def set_nonce(self, nonce: int) -> "TempoTransactionBuilder":
        """Set the nonce."""
        self.nonce = nonce
        return self

    def set_nonce_key(self, nonce_key: int) -> "TempoTransactionBuilder":
        """Set the nonce key for 2D nonce system."""
        self.nonce_key = nonce_key
        return self

    def set_valid_before(self, timestamp: int) -> "TempoTransactionBuilder":
        """Set the expiration timestamp."""
        self.valid_before = timestamp
        return self

    def set_valid_after(self, timestamp: int) -> "TempoTransactionBuilder":
        """Set the activation timestamp."""
        self.valid_after = timestamp
        return self

    def set_fee_token(self, token: BytesLike) -> "TempoTransactionBuilder":
        """Set the fee token address."""
        self.fee_token = as_address(token)
        return self

    def sponsored(self, enabled: bool = True) -> "TempoTransactionBuilder":
        """Mark the transaction as awaiting fee payer signature."""
        self.awaiting_fee_payer = enabled
        return self

    def add_call(
        self,
        to: BytesLike,
        value: int = 0,
        data: BytesLike = b"",
    ) -> "TempoTransactionBuilder":
        """Add a call to the transaction."""
        self.calls.append(Call.create(to=to, value=value, data=data))
        return self

    def add_contract_creation(
        self,
        value: int = 0,
        data: BytesLike = b"",
    ) -> "TempoTransactionBuilder":
        """Add a contract creation call."""
        self.calls.append(Call.create(to=b"", value=value, data=data))
        return self

    def add_access_list_item(
        self,
        address: BytesLike,
        storage_keys: tuple[BytesLike, ...] = (),
    ) -> "TempoTransactionBuilder":
        """Add an access list entry."""
        self.access_list.append(
            AccessListItem.create(address=address, storage_keys=storage_keys)
        )
        return self

    def build(self) -> TempoTransaction:
        """
        Build and validate the transaction.

        Returns:
            A validated, immutable TempoTransaction

        Raises:
            ValueError: If validation fails
        """
        tx = TempoTransaction(
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
            awaiting_fee_payer=self.awaiting_fee_payer,
            tempo_authorization_list=tuple(self.tempo_authorization_list),
        )
        tx.validate()
        return tx
