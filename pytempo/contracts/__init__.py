"""Tempo contract ABIs, addresses, and typed call builders.

Provides ABI definitions, canonical addresses, and typed helper classes for
Tempo precompiles and tokens, sourced from ``tempoxyz/tempo-std``.
To update ABIs, run ``scripts/tempo_abis.sh --sync``.

Typed helpers (zero ABI knowledge needed)::

    from pytempo import TempoTransaction
    from pytempo.contracts import TIP20, StablecoinDEX, ALPHA_USD, BETA_USD

    alpha = TIP20(ALPHA_USD)
    tx = TempoTransaction.create(
        ...,
        calls=(
            alpha.approve(spender=StablecoinDEX.ADDRESS, amount=10**18),
            StablecoinDEX.place(token=BETA_USD, amount=100_000_000, is_bid=True, tick=10),
        ),
    )

Raw ABIs for use with ``w3.eth.contract()``::

    from pytempo.contracts import TIP20_ABI, ALPHA_USD
    token = w3.eth.contract(address=ALPHA_USD, abi=TIP20_ABI)
    calldata = token.encode_abi("transfer", args=[recipient, amount])
"""

from .abis import (
    ACCOUNT_KEYCHAIN_ABI,
    FEE_AMM_ABI,
    FEE_MANAGER_ABI,
    NONCE_ABI,
    STABLECOIN_DEX_ABI,
    TIP20_ABI,
)
from .account_keychain import AccountKeychain
from .addresses import (
    ACCOUNT_KEYCHAIN_ADDRESS,
    ALPHA_USD,
    BETA_USD,
    FEE_MANAGER_ADDRESS,
    NONCE_ADDRESS,
    PATH_USD,
    STABLECOIN_DEX_ADDRESS,
    THETA_USD,
    TIP20_FACTORY_ADDRESS,
    TIP20_REWARDS_REGISTRY_ADDRESS,
    TIP403_REGISTRY_ADDRESS,
    VALIDATOR_CONFIG_ADDRESS,
)
from .dex import StablecoinDEX
from .fee_amm import FeeAMM
from .fee_manager import FeeManager
from .nonce import Nonce
from .tip20 import TIP20

__all__ = [
    # Typed call builders
    "TIP20",
    "StablecoinDEX",
    "AccountKeychain",
    "FeeAMM",
    "FeeManager",
    "Nonce",
    # ABIs
    "TIP20_ABI",
    "ACCOUNT_KEYCHAIN_ABI",
    "STABLECOIN_DEX_ABI",
    "FEE_MANAGER_ABI",
    "FEE_AMM_ABI",
    "NONCE_ABI",
    # Token addresses
    "PATH_USD",
    "ALPHA_USD",
    "BETA_USD",
    "THETA_USD",
    # Precompile addresses
    "ACCOUNT_KEYCHAIN_ADDRESS",
    "FEE_MANAGER_ADDRESS",
    "STABLECOIN_DEX_ADDRESS",
    "NONCE_ADDRESS",
    "TIP20_FACTORY_ADDRESS",
    "TIP20_REWARDS_REGISTRY_ADDRESS",
    "TIP403_REGISTRY_ADDRESS",
    "VALIDATOR_CONFIG_ADDRESS",
]
