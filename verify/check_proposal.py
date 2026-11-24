#!/usr/bin/env python3
"""Independent checks for proposal.json.

Re-derives the escrow address that the governance proposal's
MsgInstantiateContract2 will create (wasmd predictable address, fix_msg = false)
and compares it with the MsgCommunityPoolSpend recipient. The derivation is
first tested against the escrow created by Proposal #82.

Standard library only:
    python verify/check_proposal.py [path/to/proposal.json] [--online]

--online also queries a public Gonka REST endpoint to confirm the code_id 107
checksum and that the escrow address is still unused.
"""

import argparse
import base64
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

GOV_MODULE = "gonka10d07y265gmmuvt4z0w9aw880jnsr700j2h5m33"
CODE_ID = "107"
CODE_CHECKSUM = "94b141625b7641e6ad57266420b18a4af72eac49b8110cb92719755590b463bd"
PROPOSAL_82_SALT = "dGVzdGxhYi1kZXZuZXQtcGlsb3Q="
PROPOSAL_82_ESCROW = "gonka1g57f45qjvn0529vpgj8x8mzt8r5k4audchm3pp9pezywxwf4rexqlj8ayw"
REST = "http://node1.gonka.ai:8000/chain-api"
MAX_TITLE = 255
MAX_METADATA = 255
MAX_SUMMARY = 10200

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data, from_bits, to_bits, pad):
    acc, bits, out = 0, 0, []
    mask = (1 << to_bits) - 1
    for value in data:
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            out.append((acc >> bits) & mask)
    if pad and bits:
        out.append((acc << (to_bits - bits)) & mask)
    elif not pad and (bits >= from_bits or (acc << (to_bits - bits)) & mask):
        raise ValueError("invalid padding")
    return out


def bech32_decode(address):
    if address.lower() != address:
        raise ValueError(f"mixed-case address: {address}")
    sep = address.rfind("1")
    hrp, data = address[:sep], [BECH32_CHARSET.find(c) for c in address[sep + 1 :]]
    if sep < 1 or len(data) < 6 or -1 in data:
        raise ValueError(f"malformed address: {address}")
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError(f"bad checksum: {address}")
    return hrp, bytes(_convert_bits(data[:-6], 5, 8, pad=False))


def bech32_encode(hrp, payload):
    data = _convert_bits(payload, 8, 5, pad=True)
    checksum = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data)


def instantiate2_address(checksum_hex, creator, salt_b64):
    def length_prefixed(b):
        return len(b).to_bytes(8, "big") + b

    key = (
        length_prefixed(bytes.fromhex(checksum_hex))
        + length_prefixed(bech32_decode(creator)[1])
        + length_prefixed(base64.b64decode(salt_b64))
        + length_prefixed(b"")
    )
    digest = hashlib.sha256(hashlib.sha256(b"module").digest() + b"wasm\x00" + key).digest()
    return bech32_encode("gonka", digest)


def rest_get(path):
    try:
        with urllib.request.urlopen(f"{REST}{path}", timeout=20) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as err:
        return json.loads(err.read() or b"{}")


class Report:
    def __init__(self):
        self.failures = 0
        self.warnings = 0

    def check(self, ok, label, detail=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))
        self.failures += not ok

    def warn(self, label):
        print(f"[WARN] {label}")
        self.warnings += 1


def find_message(messages, type_url):
    found = [m for m in messages if m.get("@type") == type_url]
    if len(found) != 1:
        sys.exit(f"expected exactly one {type_url}, found {len(found)}")
    return found[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_path = Path(__file__).resolve().parent.parent / "proposal.json"
    parser.add_argument("proposal", nargs="?", type=Path, default=default_path)
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()

    proposal = json.loads(args.proposal.read_text(encoding="utf-8"))
    report = Report()

    derived_82 = instantiate2_address(CODE_CHECKSUM, GOV_MODULE, PROPOSAL_82_SALT)
    report.check(derived_82 == PROPOSAL_82_ESCROW, "derivation reproduces the Proposal #82 escrow", derived_82)

    inst = find_message(proposal["messages"], "/cosmwasm.wasm.v1.MsgInstantiateContract2")
    spend = find_message(proposal["messages"], "/cosmos.distribution.v1beta1.MsgCommunityPoolSpend")
    init = inst["msg"]

    report.check(inst["sender"] == GOV_MODULE, "instantiate sender is the governance module")
    report.check(init["governance"] == GOV_MODULE, "escrow governance is the governance module")
    report.check(spend["authority"] == GOV_MODULE, "community pool spend authority is the governance module")
    report.check(inst["code_id"] == CODE_ID, f"code_id is {CODE_ID}", inst["code_id"])
    report.check(inst["admin"] == "", "no contract admin (no migration possible)")
    report.check(inst["fix_msg"] is False and inst["funds"] == [], "fix_msg is false and no funds attached")

    escrow = instantiate2_address(CODE_CHECKSUM, inst["sender"], inst["salt"])
    salt = base64.b64decode(inst["salt"]).decode(errors="replace")
    report.check(escrow == spend["recipient"], f"escrow address (salt '{salt}') matches the spend recipient", escrow)

    payouts = init["payouts"]
    recipients = {p["recipient"] for p in payouts}
    report.check(len(recipients) == 1, "all tranches pay a single recipient", ", ".join(sorted(recipients)))
    for recipient in recipients:
        try:
            hrp, raw = bech32_decode(recipient)
            report.check(hrp == "gonka" and len(raw) == 20, "recipient is a valid gonka account address", recipient)
        except ValueError as err:
            report.check(False, "recipient is a valid gonka account address", str(err))

    report.check(all(p["denom"] == "ngonka" for p in payouts), "all tranches are in ngonka")
    days = [p["unlock_after_days"] for p in payouts]
    report.check(days == sorted(days) and init["close_after_days"] > days[-1], "unlock days ascend and close after the last unlock", f"{days}, close {init['close_after_days']}")

    total = sum(int(p["amount"]) for p in payouts)
    spent = sum(int(c["amount"]) for c in spend["amount"] if c["denom"] == "ngonka")
    tranches = " / ".join(f"{int(p['amount']) // 10**9:,}" for p in payouts)
    report.check(total == spent and len(spend["amount"]) == 1, f"tranches ({tranches} GNK) sum to the spend", f"{total / 10**9:,.0f} GNK")

    for field, limit in (("title", MAX_TITLE), ("metadata", MAX_METADATA), ("summary", MAX_SUMMARY)):
        report.check(len(proposal[field]) <= limit, f"{field} within {limit} characters", str(len(proposal[field])))

    for placeholder in sorted(set(re.findall(r"<[A-Z_]+>", json.dumps(proposal)))):
        report.warn(f"placeholder {placeholder} must be filled before submission")

    if args.online:
        code = rest_get(f"/cosmwasm/wasm/v1/code-info/{CODE_ID}")
        report.check(code.get("checksum", "").lower() == CODE_CHECKSUM, f"on-chain checksum of code {CODE_ID}", code.get("checksum", "unavailable"))
        contract = rest_get(f"/cosmwasm/wasm/v1/contract/{escrow}")
        report.check("no such contract" in contract.get("message", ""), "escrow address is still unused on-chain")

    print(f"\n{report.failures} failed, {report.warnings} warnings")
    sys.exit(1 if report.failures else 0)


if __name__ == "__main__":
    main()
