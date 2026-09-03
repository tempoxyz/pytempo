from dotenv import load_dotenv
import os

load_dotenv()

RPC_URL = os.getenv("RPC_URL", "https://rpc.testnet.tempo.xyz")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")
FACTORY_ADDRESS = os.getenv("FACTORY_ADDRESS", "0x20fc000000000000000000000000000000000000")
PATHUSD_ADDRESS = os.getenv("PATHUSD_ADDRESS", "0x20c0000000000000000000000000000000000000")
FEE_MANAGER_ADDRESS = os.getenv("FEE_MANAGER_ADDRESS", "0xfeec000000000000000000000000000000000000")
EXPLORER = os.getenv("EXPLORER", "https://explore.tempo.xyz")
