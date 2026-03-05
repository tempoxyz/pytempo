"""
Example: Tempo Address Encoding

Encode, decode, and validate Tempo bech32m addresses.

Usage:
    python examples/tempo_address.py
"""

from pytempo import TempoAddress

# --- Format a mainnet address ------------------------------------------------

addr = TempoAddress(address="0x742d35CC6634c0532925a3B844bc9e7595F2Bd28")
print(f"Mainnet address: {addr}")
# => tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0

# --- Format a zone address ---------------------------------------------------

zone_addr = TempoAddress(
    address="0x742d35CC6634c0532925a3B844bc9e7595F2Bd28",
    zone_id=1,
)
print(f"Zone 1 address:  {zone_addr}")
# => tempoz1qqqhgtf4e3nrfszn9yj68wzyhj08t90jh55q74d9uj

# --- Parse a bech32m string back to TempoAddress -----------------------------

parsed = TempoAddress.parse("tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0")
print(f"Parsed address:  0x{parsed.address.hex()}")
print(f"Parsed zone_id:  {parsed.zone_id}")

# --- Validate addresses ------------------------------------------------------

valid = TempoAddress.validate("tempo1qp6z6dwvvc6vq5efyk3ms39une6etu4a9qtj2kk0")
invalid = TempoAddress.validate("tempo1invalid")
print(f"Valid address?   {valid}")  # True
print(f"Invalid address? {invalid}")  # False
