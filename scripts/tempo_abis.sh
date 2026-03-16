#!/usr/bin/env bash
# Sync or check ABI JSON files against tempo-std Solidity interfaces.
#
# Requirements: solc (>=0.8.13), gh (GitHub CLI)
#
# Usage:
#   ./scripts/tempo_abis.sh --check   # exits 1 if drifted
#   ./scripts/tempo_abis.sh --sync    # update vendored ABIs
set -euo pipefail

case "${1:-}" in
    --check) MODE=check ;;
    --sync)  MODE=sync ;;
    *)
        echo "Usage: $0 --check | --sync" >&2
        exit 2
        ;;
esac

REPO="tempoxyz/tempo-std"
INTERFACES=(ITIP20 IAccountKeychain IStablecoinDEX IFeeManager IFeeAMM INonce)
ABI_DIR="$(cd "$(dirname "$0")/.." && pwd)/pytempo/contracts/abis"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> Downloading interfaces from $REPO"
for iface in "${INTERFACES[@]}"; do
    gh api "repos/${REPO}/contents/src/interfaces/${iface}.sol" --jq '.content' \
        | base64 -d > "${WORK_DIR}/${iface}.sol"
done

echo "==> Compiling ABIs with solc"
solc --abi --output-dir "$WORK_DIR/abi" "${WORK_DIR}"/*.sol >/dev/null

if [ "$MODE" = sync ]; then
    echo "==> Writing ABIs to $ABI_DIR"
    mkdir -p "$ABI_DIR"
    for iface in "${INTERFACES[@]}"; do
        python3 -c "
import json, sys
abi = json.loads(sys.stdin.read())
json.dump(abi, open(sys.argv[1], 'w'), indent=2)
print(f'    {sys.argv[2]} ({len(abi)} entries)')
" "${ABI_DIR}/${iface}.json" "${iface}.json" < "${WORK_DIR}/abi/${iface}.abi"
    done
    echo "==> Done"
else
    echo "==> Checking ABIs against $ABI_DIR"
    DRIFT=0
    for iface in "${INTERFACES[@]}"; do
        upstream=$(python3 -c "import json,sys; json.dump(json.loads(sys.stdin.read()), sys.stdout, indent=2, sort_keys=True)" < "${WORK_DIR}/abi/${iface}.abi")
        vendored=$(python3 -c "import json,sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2, sort_keys=True)" < "${ABI_DIR}/${iface}.json")
        if [ "$upstream" != "$vendored" ]; then
            echo "    DRIFT: ${iface}.json"
            DRIFT=1
        else
            echo "    OK:    ${iface}.json"
        fi
    done
    if [ "$DRIFT" -eq 1 ]; then
        echo "==> ABIs are out of sync. Run ./scripts/tempo_abis.sh --sync to update."
        exit 1
    fi
    echo "==> All ABIs are in sync."
fi
