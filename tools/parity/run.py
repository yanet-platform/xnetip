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



def extension_corpus(seed):
    """Exercise additive APIs without changing the established core corpus."""
    randomizer = random.Random(seed ^ 0xE0148)
    records = []

    def emit(operation, *values):
        records.append(operation + " " + " ".join(f"{value:x}" for value in values))

    def text(operation, value):
        records.append(operation + " " + (value.hex() or "-"))

    for width, family in [(32, "4"), (128, "6")]:
        full = (1 << width) - 1
        for idx in range(1000):
            mask = prefix_mask(width, randomizer.randrange(width + 1)) if idx % 2 else randomizer.getrandbits(width)
            address = randomizer.getrandbits(width) & mask
            child = mask
            for position in randomizer.sample(range(width), randomizer.randrange(5)):
                child |= 1 << position
            if idx % 3 == 0:
                child = randomizer.getrandbits(width)
            prefix = randomizer.randrange(width + 2)
            # Prefixes are decimal in the line protocol, unlike the bit words.
            records.append(f"s{family} {address:x} {mask:x} {child:x} {prefix}")
        for idx in range(750):
            host_bits = randomizer.choice([0, 1, 2, min(32, width), min(63, width), min(64, width), min(65, width), width])
            positions = randomizer.sample(range(width), host_bits)
            mask = full
            for position in positions:
                mask ^= 1 << position
            if idx % 3 == 0:
                mask = prefix_mask(width, width-host_bits)
            address = randomizer.getrandbits(width) & mask
            if width == 128 and idx % 11 == 0:
                mask |= prefix_mask(128, 96)
                address = (0xffff << 32) | (address & 0xffffffff)
            script = []
            for step in range(16):
                skip = randomizer.choice([0, 1, 2, 7, 63, (1 << 64)-1, randomizer.getrandbits(64)])
                if step < 4:
                    skip = randomizer.randrange(3)
                script.extend([randomizer.choice(["f", "b"]), f"{skip:x}"])
            records.append(f"i{family} {address:x} {mask:x} " + " ".join(script))
        # Pin maximum skips from a fresh cursor on both sides of 64-bit count
        # overflow, including scattered host positions and nonzero base bits.
        for host_bits in sorted({0, 1, min(32, width), min(63, width), min(64, width), min(65, width), width}):
            for scattered in [False, True]:
                mask = prefix_mask(width, width-host_bits)
                if scattered:
                    mask = full
                    for position in [(idx*(width//2+1)) % width for idx in range(host_bits)]:
                        mask ^= 1 << position
                address = int("a5"*(width//8), 16) & mask
                for direction, opposite in [("f", "b"), ("b", "f")]:
                    records.append(f"i{family} {address:x} {mask:x} {direction} ffffffffffffffff {opposite} 0 {direction} 1 {opposite} ffffffffffffffff {direction} 0")
        for idx in range(500):
            count = [0, 1, 2, 3, 4, 15, 16, 31, 32, 63, 64, 128, 256][idx % 13]
            networks = []
            for position in range(count):
                mask = full ^ randomizer.getrandbits(8) if idx % 3 else randomizer.getrandbits(width)
                address = randomizer.randrange(1 << min(width, 16)) & mask
                if networks and position % 5 == 0:
                    address, mask = randomizer.choice(networks)
                networks.append((address, mask))
            randomizer.shuffle(networks)
            values = [value for network in networks for value in network]
            emit("j"+family, *values)
    for idx in range(1000):
        value = randomizer.getrandbits(64 if idx % 5 == 0 else 48)
        emit("m", value)
        identifier = randomizer.getrandbits(64)
        if idx % 2:
            identifier = (identifier & ~(0xffff << 24)) | (0xfffe << 24)
        emit("e", identifier)
        group4 = randomizer.getrandbits(32)
        group6 = randomizer.getrandbits(128)
        if idx % 2:
            group4 = (group4 & 0x0fffffff) | 0xe0000000
            group6 |= 0xff << 120
        emit("v4", group4)
        emit("v6", group6)
        digits = f"{randomizer.getrandbits(48):012x}"
        if idx % 3 == 0:
            mac = ":".join(digits[position:position+2] for position in range(0, 12, 2))
        elif idx % 3 == 1:
            mac = "-".join(digits[position:position+2] for position in range(0, 12, 2))
        else:
            mac = ".".join(digits[position:position+4] for position in range(0, 12, 4))
        if idx % 2:
            mac = mac.upper()
        encoded = mac.encode()
        if idx % 5 == 0:
            position = randomizer.randrange(len(encoded))
            encoded = encoded[:position] + bytes([randomizer.randrange(256)]) + encoded[position+1:]
        text("mt", encoded)
    for value in [0, 1, (1 << 48)-1, 1 << 48, (1 << 64)-1]:
        emit("m", value)
    for value in [0, 0xffffffff, 0xdfffffff, 0xe0000000, 0xefffffff, 0xf0000000]:
        emit("v4", value)
    for value in [0, (0xff << 120)-1, 0xff << 120, (1 << 128)-1, (0xffff << 32) | 0xe0000001]:
        emit("v6", value)
    for value in [b"", b"aabbccddeeff", b"AA-BB-CC-DD-EE-FF", b"aabb.ccdd.eeff", b"aa:bb:cc:dd:ee:ff:00:11", b"aa:bb-cc:dd:ee:ff", b"aa:bb:cc:dd:ee:gg"]:
        text("mt", value)
    for idx in range(1000):
        width = randomizer.choice([32, 128])
        address = ipaddress.IPv4Address(randomizer.getrandbits(32)) if width == 32 else ipaddress.IPv6Address(randomizer.getrandbits(128))
        network = f"{address}/{randomizer.randrange(width+1)}".encode()
        text("ta", network)
        for tail in randomizer.sample([b" allow", b" deny", b"%eth0", b"\xfftail", b",next", b":8080", b"/8", b"allow", b"\n"], 2):
            text("tn", network+tail)
    for value in [b"", b" ", b"::/256", b"1.2.3.4/24.1", b"::1\x00tail", b"fe80::1%eth0", b"1.2.3.4:8080", b"1.2.3.4abcd", b"::ffff:192.0.2.1/120 allow"]:
        text("ta", value)
        text("tn", value)
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
    records = corpus(arguments.seed) + extension_corpus(arguments.seed)
    contracts = json.loads((TOOLS / "contracts.json").read_text())
    contract_start = len(records)
    records += [case.get("operation", "t") + " " + (case["input"].encode().hex() or "-") for case in contracts]
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
