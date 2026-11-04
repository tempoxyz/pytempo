"""pytempo's core must import without web3 installed."""

import subprocess
import sys

_SCRIPT = """
import sys
sys.modules["web3"] = None  # make any `import web3` raise ImportError
import pytempo
from pytempo import Call, KeychainSignature, TempoTransaction, sign_tx_access_key
import pytempo.models, pytempo.signatures, pytempo.contracts
from pytempo.contracts import TIP20, ALPHA_USD
TIP20(ALPHA_USD).transfer(to="0x" + "11" * 20, amount=1)
assert "web3" not in {m.split(".")[0] for m in sys.modules if sys.modules[m] is not None}
"""


def test_core_imports_without_web3():
    subprocess.run([sys.executable, "-c", _SCRIPT], check=True)
