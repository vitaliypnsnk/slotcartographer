# slotcartographer — map Solidity storage slots from human expressions (offline)

**slotcartographer** converts expressions like `balances[0xabc]` and
`users[0xabc].nonce` into exact **storage slot keys** you can pass to
`eth_getStorageAt`. It understands mappings, nested mappings, dynamic/static
arrays, and struct field offsets — all from a tiny layout JSON. No RPC needed.

## Why this is useful

- You know the layout from code review but don’t want to re-derive the math.
- You’re writing scripts/tests and need **deterministic slot keys** fast.
- Great for audits and CI checks (it prints the **path** it took).

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
