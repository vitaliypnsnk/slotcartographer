#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
slotcartographer — Map Solidity storage slots from human expressions (offline).

Examples
  # Quick ERC20 preset (typical OZ layout: balances at slot 0, allowance at slot 1)
  $ python slotcartographer.py preset erc20-basic > layout.json

  # Compute a few slots
  $ python slotcartographer.py calc layout.json \
      "balances[0xCAfEcafeCAfEcafeCAFecAfEcafEcAFecaFEcAFe]" \
      "allowance[0xAlice][0xBob]" \
      --pretty --svg badge.svg --json out.json

  # Dynamic arrays & nested mappings
  $ python slotcartographer.py calc layout.json "orders[5]" "userData[0xabc].nonce" --pretty
"""

import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
from eth_utils import keccak, to_checksum_address

# ----------------------- utilities -----------------------

def strip0x(s: str) -> str:
    return s[2:] if isinstance(s, str) and s.lower().startswith("0x") else s

def pad32(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")

def as_uint256_bytes(x: int) -> bytes:
    if x < 0:
        raise click.ClickException("Index/slot must be non-negative")
    return pad32(x.to_bytes((x.bit_length()+7)//8 or 1, "big"))

def as_key_bytes(val: str, keytype: str) -> bytes:
    """
    Convert a mapping key to 32-byte word as Solidity does before hashing.
    Supports: address, uint256/int256 (as uint256), bytes32, string/bytes (expects 0x..)
    """
    kt = keytype.strip().lower()
    v = str(val)

    if kt == "address":
        # accept name or hex; always fold to 20-byte then left-pad to 32
        try:
            addr = to_checksum_address(v)
        except Exception:
            if v.lower().startswith("0x") and len(strip0x(v)) == 40:
                addr = "0x" + strip0x(v)
            else:
                raise click.ClickException(f"Invalid address key: {v}")
        return pad32(bytes.fromhex(strip0x(addr)))
    if kt in ("uint256","int256","uint","int"):
        if v.lower().startswith("0x"):
            n = int(v, 16)
        else:
            n = int(v)
        return as_uint256_bytes(n)
    if kt == "bytes32":
        h = strip0x(v)
        if len(h) != 64:
            raise click.ClickException("bytes32 key must be 32 bytes (64 hex)")
        return bytes.fromhex(h)
    if kt in ("string","bytes"):
        # expect hex for determinism (already ABI-encoded in app-specific schemes)
        if not v.lower().startswith("0x"):
            raise click.ClickException(f"{kt} key must be 0x-hex for slotcalc")
        raw = bytes.fromhex(strip0x(v))
        if len(raw) > 32:
            # Solidity mapping for bytes/string uses keccak(raw) as the key "value"
            return keccak(raw)
        return pad32(raw)
    # default: treat as uint
    if v.lower().startswith("0x"):
        n = int(v, 16)
    else:
        n = int(v)
    return as_uint256_bytes(n)

def keccak_word(a: bytes, b: bytes) -> bytes:
    return keccak(a + b)

# ----------------------- models -----------------------

@dataclass
class SlotResult:
    expr: str
    slot_uint: int
    slot_hex: str
    path: List[str]     # descriptive steps
    notes: List[str]

# ----------------------- layout & parsing -----------------------

"""
Layout JSON shape (concise):

{
  "balances":  { "type": "mapping(address=>uint256)", "slot": 0 },
  "allowance": { "type": "mapping(address=>mapping(address=>uint256))", "slot": 1 },
  "orders":    { "type": "uint256[]", "slot": 2 },
  "users":     {
      "type": "mapping(address=>struct)",
      "slot": 5,
      "struct": { "nonce": 0, "balance": 1 }    # word offsets within the user struct
  },
  "config":    { "type": "struct", "slot": 10, "struct": { "owner": 0, "paused": 1 } }
}

"""

TYPE_RE = re.compile(r"""
    (?P<base>
        mapping\(
            (?P<key>[^)=]+)
            =>
            (?P<value>.+)
        \)
      | (?P<dyn>.+)\[\]
      | (?P<static>.+)\[(?P<len>\d+)\]
      | struct
      | address | bool | bytes32 | string | bytes | uint256 | int256 | uint | int
    )
""", re.VERBOSE)

def parse_type(t: str) -> Dict[str, Any]:
    t = t.strip()
    m = TYPE_RE.fullmatch(t)
    if not m:
        raise click.ClickException(f"Unsupported type: {t}")
    if m.group("base").startswith("mapping("):
        # mapping(key=>value)
        inside = t[len("mapping("):-1]
        key, value = inside.split("=>", 1)
        return {"kind":"mapping", "key": key.strip(), "value": value.strip()}
    if m.group("dyn"):
        return {"kind":"dynarray", "elem": m.group("dyn").strip()}
    if m.group("static"):
        return {"kind":"staticarray", "elem": m.group("static").strip(), "len": int(m.group("len"))}
    if t == "struct":
        return {"kind":"struct"}
    # primitive
    return {"kind":"primitive", "name": t}

EXPR_RE = re.compile(r"""
    ^
    (?P<var>[A-Za-z_][A-Za-z0-9_]*)
    (?P<trail>
        (?:\[[^\]]+\]|\.[A-Za-z_][A-Za-z0-9_]*)*
    )
    $
""", re.VERBOSE)

def parse_expr(expr: str) -> Tuple[str, List[Any]]:
    """
    Parse "allowance[0xAlice][0xBob]" → ("allowance", ["0xAlice","0xBob"])
    Parse "users[0xabc].nonce" → ("users", ["0xabc", ('.', 'nonce')])
    """
    s = expr.strip()
    m = EXPR_RE.match(s)
    if not m:
        raise click.ClickException(f"Bad expression: {expr}")
    var = m.group("var")
    trail = m.group("trail")
    parts: List[Any] = []
    i = 0
    while i < len(trail):
        if trail[i] == "[":
            j = trail.find("]", i)
            if j == -1:
                raise click.ClickException("Unclosed [ in expression")
            val = trail[i+1:j].strip()
            parts.append(val)
            i = j + 1
        elif trail[i] == ".":
            j = i + 1
            while j < len(trail) and (trail[j].isalnum() or trail[j] == "_"):
                j += 1
            parts.append((".", trail[i+1:j]))
            i = j
        else:
            i += 1
    return var, parts

# ----------------------- slot computation -----------------------

def compute_slot(layout: Dict[str, Any], var: str, parts: List[Any]) -> SlotResult:
    if var not in layout:
        raise click.ClickException(f"Variable '{var}' not found in layout")
    entry = layout[var]
    if isinstance(entry, int):
        entry = {"type": "uint256", "slot": entry}
    if "type" not in entry or "slot" not in entry:
        raise click.ClickException(f"Layout entry for {var} must have type & slot")

    tinfo = parse_type(entry["type"])
    base_slot = int(entry["slot"])
    path = [f"{var}@{base_slot}"]
    notes: List[str] = []

    def slot_for_mapping(base: int, keyval: str, keytype: str) -> int:
        a = as_key_bytes(keyval, keytype)
        b = as_uint256_bytes(base)
        h = keccak(a + b)
        return int.from_bytes(h, "big")

    cur_slot = base_slot
    cur_type = tinfo

    i = 0
    while i < len(parts):
        step = parts[i]

        if isinstance(cur_type, dict) and cur_type.get("kind") == "mapping":
            if isinstance(step, tuple) and step[0] == ".":
                raise click.ClickException("Cannot access field on mapping without key")
            keyval = step
            cur_slot = slot_for_mapping(cur_slot, keyval, cur_type["key"])
            path.append(f"map[{cur_type['key']}={keyval}]@{cur_slot}")
            # descend into value type
            cur_type = parse_type(cur_type["value"])
            i += 1
            continue

        if isinstance(cur_type, dict) and cur_type.get("kind") == "dynarray":
            if isinstance(step, tuple) and step[0] == ".":
                raise click.ClickException("Cannot access field on array without index")
            # dynamic array base = keccak(slot)
            base = int.from_bytes(keccak(as_uint256_bytes(cur_slot)), "big")
            idx = int(step, 0)
            cur_slot = base + idx
            path.append(f"dyn[{idx}]@{cur_slot}")
            cur_type = parse_type(cur_type["elem"])
            i += 1
            continue

        if isinstance(cur_type, dict) and cur_type.get("kind") == "staticarray":
            if isinstance(step, tuple) and step[0] == ".":
                raise click.ClickException("Cannot access field on array without index")
            idx = int(step, 0)
            # assume word-sized elements
            cur_slot = cur_slot + idx
            path.append(f"arr[{idx}]@{cur_slot}")
            cur_type = parse_type(cur_type["elem"])
            i += 1
            continue

        if isinstance(cur_type, dict) and cur_type.get("kind") in ("primitive", "struct"):
            # struct field or terminal
            if isinstance(step, tuple) and step[0] == ".":
                field = step[1]
                struct = entry.get("struct") if cur_type["kind"] == "struct" else entry.get("struct")
                # If we're under a mapping/array of structs, prefer the 'struct' from the original entry
                struct = entry.get("struct") or {}
                if field not in struct:
                    raise click.ClickException(f"Unknown struct field '{field}' for {var}")
                off = int(struct[field])
                cur_slot = cur_slot + off
                path.append(f".{field}(+{off})@{cur_slot}")
                # primitive inside struct; stop if next is not another field
                i += 1
                # After field, treat as primitive
                cur_type = {"kind":"primitive","name":"uint256"}
                continue
            else:
                # no field; terminal value is at current slot
                break

        raise click.ClickException(f"Cannot apply step {step} on type {cur_type}")

    return SlotResult(expr=f"{var}{''.join(['['+p+']' if not isinstance(p, tuple) else '.'+p[1] for p in parts])}",
                      slot_uint=cur_slot,
                      slot_hex="0x" + cur_slot.to_bytes(32, "big").hex(),
                      path=path,
                      notes=notes)

# ----------------------- CLI -----------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """slotcartographer — Map Solidity storage slots from human expressions."""
    pass

@cli.command("calc")
@click.argument("layout_path", type=str)
@click.argument("expressions", nargs=-1)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON results.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge.")
@click.option("--pretty", is_flag=True, help="Readable console output.")
def calc_cmd(layout_path, expressions, json_out, svg_out, pretty):
    """Compute slot keys for one or more expressions using a layout JSON."""
    if not expressions:
        raise click.ClickException("Provide at least one expression")
    with open(layout_path, "r", encoding="utf-8") as f:
        layout = json.load(f)

    results: List[SlotResult] = []
    for ex in expressions:
        var, parts = parse_expr(ex)
        res = compute_slot(layout, var, parts)
        results.append(res)

    if pretty:
        for r in results:
            click.echo(f"{r.expr:<48} → slot {r.slot_uint} ({r.slot_hex})")
            click.echo(f"  path: {'  →  '.join(r.path)}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        click.echo(f"Wrote JSON: {json_out}")

    if svg_out:
        color = "#3fb950"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="48" role="img" aria-label="slotcartographer">
  <rect width="720" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    slotcartographer: computed {len(results)} slot(s)
  </text>
  <circle cx="695" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        click.echo(json.dumps([asdict(r) for r in results], indent=2))

@cli.command("preset")
@click.argument("name", type=click.Choice(["erc20-basic","erc721-basic"], case_sensitive=False))
def preset_cmd(name):
    """Emit a starter layout JSON preset."""
    if name == "erc20-basic":
        layout = {
            "balances":  { "type": "mapping(address=>uint256)", "slot": 0 },
            "allowance": { "type": "mapping(address=>mapping(address=>uint256))", "slot": 1 },
            "totalSupply": { "type": "uint256", "slot": 2 }
        }
    else:  # erc721-basic
        layout = {
            "ownerOf":   { "type": "mapping(uint256=>address)", "slot": 0 },
            "balances":  { "type": "mapping(address=>uint256)", "slot": 1 },
            "approvals": { "type": "mapping(uint256=>address)", "slot": 2 },
            "operatorApproval": { "type": "mapping(address=>mapping(address=>bool))", "slot": 3 }
        }
    click.echo(json.dumps(layout, indent=2))

@cli.command("explain")
def explain_cmd():
    """Print a short refresher of slot math rules."""
    msg = """Rules (Solidity storage):

• mapping(K => V) at slot p:
    slot(key) = keccak( pad32(key) ++ pad32(p) )

• mapping nested: fold above multiple times with each key in order.

• dynamic array T[] at slot p:
    base = keccak( pad32(p) )
    element i (word-sized) at: base + i

• static array T[N] at slot p:
    element i (word-sized) at: p + i

• struct fields:
    field at offset o lives at: slot + o
    (Works at top-level or under a mapping/array element.)

All arithmetic is over uint256 words; results are shown as 32-byte hex for eth_getStorageAt.
"""
    click.echo(msg)

if __name__ == "__main__":
    cli()
