# Tempo Payment Demo (web3.py)

This example demonstrates a minimal end-to-end payment flow on the Tempo testnet
using web3.py. It is intended as a practical, copy-ready reference for developers.

What it shows:
- Requesting test funds via the Tempo faucet (`tempo_fundAddress`)
- Building, signing, and broadcasting a TIP-20 (PATHUSD) transfer
- A small smoke test and instructions to run locally

Important: This is a community example. Use a test-only private key and never commit secrets.

Quickstart:
1. Create virtualenv:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
2. Fill .env from .env.example.
3. Run demo:
python -m src.main
4. Sign & send:
python -m src.send_tx
