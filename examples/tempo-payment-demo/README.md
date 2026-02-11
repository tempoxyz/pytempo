# Tempo Python Payment Demo

A minimal, practical Python example demonstrating end-to-end payment flow on Tempo testnet using **web3.py**.

## 🎯 What This Demonstrates

- ✅ Request test funds from Tempo faucet (`tempo_fundAddress`)
- ✅ Build, sign, and broadcast TIP-20 (PATHUSD) transfers
- ✅ Verify transactions on Tempo explorer
- ✅ Secure key management with environment variables

## 🔗 Live Example

A real test transaction was successfully broadcast during development:

- **Transaction Hash**: `b98e091a23a761e25d8ff4e421ab4f201f2019ecd6c9ee549168ee4bdd73347d`
- **Explorer Link**: https://explore.tempo.xyz/tx/b98e091a23a761e25d8ff4e421ab4f201f2019ecd6c9ee549168ee4bdd73347d

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Access to Tempo testnet

## 🚀 Quick Start

### 1. Setup Environment
```bash
# Navigate to example directory
cd examples/tempo-payment-demo

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure
```bash
# Copy environment template
cp .env.example .env

# Edit .env with your test credentials
nano .env  # or use your favorite editor
```

Your `.env` should look like:
```env
RPC_URL=https://rpc.testnet.tempo.xyz
PRIVATE_KEY=your_test_private_key_here_without_0x
```

⚠️ **Security Warning**: Use **test-only** private keys. Never commit real keys!

### 3. Run the Demo
```bash
# Request funds and check balance
python -m src.main

# Send a test transaction
python -m src.send_tx
```

## 📁 Project Structure
```
tempo-payment-demo/
├── src/
│   ├── __init__.py
│   ├── client.py      # Web3 client wrapper
│   ├── config.py      # Environment configuration loader
│   ├── faucet.py      # Faucet interaction helper
│   ├── payment.py     # Payment utilities (TIP-20 transfers)
│   ├── send_tx.py     # Transaction sender script
│   └── main.py        # Main demo entrypoint
├── requirements.txt   # Python dependencies (web3, python-dotenv)
├── .env.example       # Environment template
├── .gitignore         # Git ignore rules (venv, .env)
└── README.md          # This file
```

## 💻 Usage Examples

### Check Balance
```python
from src.client import get_web3_client
from src.config import Config

config = Config()
w3, account = get_web3_client(config)

balance = w3.eth.get_balance(account.address)
print(f"Balance: {w3.from_wei(balance, 'ether')} PATHUSD")
```

### Send TIP-20 Transfer
```python
from src.payment import send_tip20_transfer

tx_hash = send_tip20_transfer(
    w3=w3,
    account=account,
    to_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    amount_in_ether=10.0
)

print(f"Transaction sent: {tx_hash.hex()}")
print(f"Explorer: https://explore.tempo.xyz/tx/{tx_hash.hex()}")
```

### Request Faucet Funds
```python
from src.faucet import request_faucet_funds

success = request_faucet_funds(w3, account.address)
if success:
    print("✅ Funds received!")
```

## 🌐 Network Details

| Parameter | Value |
|-----------|-------|
| **Network** | Tempo Testnet (Andantino) |
| **Chain ID** | 42429 |
| **RPC URL** | https://rpc.testnet.tempo.xyz |
| **WebSocket** | wss://rpc.testnet.tempo.xyz |
| **Explorer** | https://explore.tempo.xyz |
| **Currency** | PATHUSD (TIP-20) |

## 🔧 Troubleshooting

### Insufficient Funds Error
```bash
# Request funds from faucet
python -m src.faucet
```

### Connection Issues

- Verify `RPC_URL` in `.env` is correct
- Check network connectivity
- Ensure you're using testnet, not mainnet

### Transaction Failed

- Check you have sufficient balance for gas + transfer amount
- Verify recipient address format (must start with 0x)
- Ensure private key is valid (64 hex characters, no 0x prefix)

### Import Errors
```bash
# Make sure you're in the venv and dependencies are installed
source venv/bin/activate
pip install -r requirements.txt
```

## 🔐 Security Best Practices

- ✅ Use `.env` for sensitive data (git-ignored by default)
- ✅ **Never** commit private keys to version control
- ✅ Use **test-only keys** for testnet (generate at https://vanity-eth.tk/)
- ✅ For production, use secure vaults (AWS KMS, HashiCorp Vault, GitHub Secrets)
- ✅ Rotate keys regularly
- ✅ Never share private keys via chat, email, or screenshots

## 📚 Resources

- [Tempo Documentation](https://docs.tempo.xyz)
- [Tempo Testnet Faucet](https://docs.tempo.xyz/quickstart/faucet)
- [TIP-20 Token Standard](https://docs.tempo.xyz/protocol/tip20/overview)
- [web3.py Documentation](https://web3py.readthedocs.io/)
- [Tempo Python SDK](https://github.com/tempoxyz/pytempo)

## 🤝 Contributing

Found a bug or want to improve this example? Contributions are welcome!

1. Fork the [pytempo repository](https://github.com/tempoxyz/pytempo)
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes (`git commit -m 'feat: add some feature'`)
4. Push to the branch (`git push origin feature/my-improvement`)
5. Open a Pull Request

## ⚠️ Important Notes

- This is a **community example** for educational purposes
- Use **test-only** private keys and testnet funds
- Not audited for production use
- Tempo is still under development - API may change

## 📄 License

This example follows the pytempo repository license.

See [LICENSE](../../LICENSE) for details.

---

**Need help?** Check the [Tempo Discord](https://discord.gg/tempo) or [GitHub Issues](https://github.com/tempoxyz/pytempo/issues).
