#!/usr/bin/env python3
"""Compare deterministic network corpora with a pinned Rust reference."""

import argparse
import collections
import ipaddress
import json
import pathlib
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = pathlib.Path(__file__).resolve().parent


def prefix_mask(width, prefix):
    return ((1 << width) - 1) ^ ((1 << (width - prefix)) - 1)


def corpus(seed):
    randomizer = random.Random(seed)
    records = []

    def emit(operation, *pairs):
        records.append(operation + " " + " ".join(f"{value:x}" for pair in pairs for value in pair))

    def mask(width, kind):
        if kind == 0:
            return randomizer.getrandbits(width)
        if kind == 1:
            return prefix_mask(width, randomizer.randrange(width + 1))
        if kind == 2:
            return ((1 << width) - 1) ^ randomizer.getrandbits(8)
        if kind == 3:
            return randomizer.choice([0, (1 << width) - 1, 1, 1 << (width - 1), 0xAAAAAAAA, 0x55555555])
        if width == 128:
            return (prefix_mask(64, randomizer.randrange(65)) << 64) | prefix_mask(64, randomizer.randrange(65))
        return randomizer.getrandbits(width)

    for width, family in [(32, "4"), (128, "6")]:
        for idx in range(12000):
            first_mask = mask(width, idx % 5)
            first = randomizer.getrandbits(width) & first_mask
            second_mask = mask(width, (idx // 5) % 5)
            second = randomizer.getrandbits(width) & second_mask
            mode = idx % 8
            if mode == 0:
                second_mask, second = first_mask, first
            elif mode == 1:
                second_mask = first_mask | second_mask
                second = (first | (randomizer.getrandbits(width) & ~first_mask)) & second_mask
            elif mode == 2:
                second_mask = first_mask & second_mask
                second = first & second_mask
            elif mode == 3:
                second_mask = first_mask
                if first_mask:
                    bit = randomizer.choice([bit for bit in range(width) if first_mask >> bit & 1])
                    second = first ^ (1 << bit)
            elif mode == 4:
                second_mask = first_mask
                second = first ^ (first_mask & -first_mask)
            if width == 128 and mode == 5:
                first = (0xFFFF << 32) | (first & 0xFFFFFFFF)
                first_mask = prefix_mask(128, 96) | (first_mask & 0xFFFFFFFF)
                second = (0xFFFF << 32) | (second & 0xFFFFFFFF)
                second_mask = prefix_mask(128, 96) | (second_mask & 0xFFFFFFFF)
            emit("p" + family, (first, first_mask), (second, second_mask))
        for idx in range(1000):
            first, last = randomizer.getrandbits(width), randomizer.getrandbits(width)
            if idx % 3 == 0:
                first, last = sorted((first, last))
            elif idx % 3 == 1:
                first = randomizer.getrandbits(width)
                last = min((1 << width) - 1, first + randomizer.randrange(10000))
            emit("r" + family, (first, last))
        boundaries = [0, 1, 2, (1 << width) - 1, (1 << width) - 2]
        boundaries += [(1 << bit) + offset for bit in [width // 2 - 1, width // 2, width // 2 + 1, width - 1] for offset in [-1, 0, 1]]
        for first in boundaries:
            for last in boundaries:
                emit("r" + family, (first, last))
        for operation in ["a", "c"]:
            for _ in range(750):
                networks = []
                for idx in range(randomizer.randrange(1, 35)):
                    netmask = prefix_mask(width, randomizer.randrange(width - 8, width + 1)) if operation == "c" else mask(width, idx % 5)
                    address = randomizer.randrange(256) & netmask
                    if networks and idx % 4 == 0:
                        address, netmask = networks[-1]
                    networks.append((address, netmask))
                emit(operation + family, *networks)
    for _ in range(2000):
        networks = []
        for _ in range(randomizer.randrange(1, 30)):
            netmask = (prefix_mask(64, randomizer.randrange(60, 65)) << 64) | prefix_mask(64, randomizer.randrange(60, 65))
            address = ((randomizer.randrange(16) << 64) | randomizer.randrange(16)) & netmask
            networks.append((address, netmask))
        emit("b6", *networks)
    full = (1 << 128) - 1
    emit("b6", (0, full), (1 << 64, full), ((1 << 64) | 2, full), (2, (prefix_mask(64, 63) << 64) | prefix_mask(64, 64)))
    for _ in range(2000):
        width = randomizer.choice([32, 128])
        address = ipaddress.ip_address(randomizer.getrandbits(width)) if width == 32 else ipaddress.IPv6Address(randomizer.getrandbits(width))
        suffix = str(randomizer.randrange(width + 1)) if randomizer.randrange(2) else str(ipaddress.IPv4Address(randomizer.getrandbits(32)) if width == 32 else ipaddress.IPv6Address(randomizer.getrandbits(128)))
        records.append("t " + f"{address}/{suffix}".encode().hex())
    return records


def command(arguments, **kwargs):
    return subprocess.run([str(argument) for argument in arguments], check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-source", required=True, type=pathlib.Path)
    parser.add_argument("--seed", type=int, default=20261102)
    parser.add_argument("--output", type=pathlib.Path, help="Save corpus and mismatch details for replay")
    arguments = parser.parse_args()
    reference = arguments.rust_source.resolve()
    expected_revision = (TOOLS / "rust-revision").read_text().strip()
    revision = command(["git", "rev-parse", "HEAD"], cwd=reference, capture_output=True).stdout.strip()
    if revision != expected_revision:
        parser.error(f"reference is {revision}, expected {expected_revision}")
    command(["git", "diff", "--exit-code", "HEAD", "--", "src"], cwd=reference)
    records = corpus(arguments.seed)
    contracts = json.loads((TOOLS / "contracts.json").read_text())
    contract_start = len(records)
    records += ["t " + case["input"].encode().hex() for case in contracts]
    inputs = "\n".join(records) + "\n"
    outputs = {}
    with tempfile.TemporaryDirectory(prefix="xnetip-parity-") as temporary:
        directory = pathlib.Path(temporary)
        command(["rustc", "--edition=2024", "--crate-type=rlib", "--crate-name=netip", reference / "src/lib.rs", "--out-dir", directory])
        command(["rustc", "--edition=2024", TOOLS / "rust/main.rs", "--extern", f"netip={directory / 'libnetip.rlib'}", "-o", directory / "rust-probe"])
        command(["go", "build", "-o", directory / "go-probe", "./tools/parity/go"], cwd=ROOT)
        for language in ["rust", "go"]:
            outputs[language] = command([directory / f"{language}-probe"], input=inputs, capture_output=True).stdout.splitlines()
            if len(outputs[language]) != len(records):
                raise RuntimeError(f"{language}: expected {len(records)} results, got {len(outputs[language])}")
    mismatches = []
    for idx, record in enumerate(records):
        rust, go = outputs["rust"][idx], outputs["go"][idx]
        if idx < contract_start:
            valid = rust == go
        else:
            case = contracts[idx - contract_start]
            valid = rust == case["rust"] and go == case["go"]
        if not valid:
            mismatches.append({"index": idx, "input": record, "rust": rust, "go": go})
    summary = {"rust_revision": revision, "seed": arguments.seed, "records": len(records), "by_operation": dict(collections.Counter(record.split()[0] for record in records)), "mismatches": len(mismatches)}
    print(json.dumps(summary, indent=2))
    if arguments.output:
        arguments.output.mkdir(parents=True, exist_ok=True)
        (arguments.output / "corpus.txt").write_text(inputs)
        (arguments.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (arguments.output / "mismatches.json").write_text(json.dumps(mismatches, indent=2) + "\n")
    if mismatches:
        print(json.dumps(mismatches[:20], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
