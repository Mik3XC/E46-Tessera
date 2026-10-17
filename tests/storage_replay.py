#!/usr/bin/env python3
"""Compare two nodes on independent copies of public block/mempool fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time


def compact(data, offset):
    prefix = data[offset]
    offset += 1
    width = {253: 2, 254: 4, 255: 8}.get(prefix, 0)
    return (int.from_bytes(data[offset:offset + width], 'little'), offset + width) if width else (prefix, offset)


def address(payload):
    hrp = 'te46'
    words, accumulator, bits = [0], 0, 0
    for value in payload:
        accumulator = (accumulator << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
    if bits:
        words.append((accumulator << (5 - bits)) & 31)
    chk = 1
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + words + [0] * 6
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                chk ^= generator
    chk ^= 0x2bc830a3
    words += [(chk >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join('qpzry9x8gf2tvdw0s3jn54khce6mua7l'[v] for v in words)


def addresses(records):
    found = set()
    for path in records:
        data = path.read_bytes()
        count, pos = compact(data, 128)
        for _ in range(count):
            length, pos = compact(data, pos)
            raw = data[pos:pos + length]
            pos += length
            inputs, cursor = compact(raw, 4)
            cursor += inputs * 40
            outputs, cursor = compact(raw, cursor)
            for _ in range(outputs):
                kind = raw[cursor + 8]
                cursor += 9
                size, cursor = compact(raw, cursor)
                payload = raw[cursor:cursor + size]
                cursor += size
                if kind == 0:
                    assert size == 32
                    found.add(address(payload))
                else:
                    assert kind == 3, 'Extend address discovery before using non-single-owner fixtures'
    return sorted(found)


def cli(node, directory, *words):
    return subprocess.check_output([node, '--datadir', str(directory), *map(str, words)], timeout=90)


def start(node, directory, log):
    assert len(os.fsencode((directory / 'control.sock').resolve())) < 100
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    proc = subprocess.Popen([node, '--datadir', str(directory), 'serve', '--listen', f'127.0.0.1:{port}'], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('Node exited; inspect daemon log')
            if (directory / 'control.sock').exists():
                cli(node, directory, 'status')
                return proc
            time.sleep(.1)
        raise TimeoutError('Node startup timed out')
    except BaseException:
        proc.terminate()
        proc.wait(timeout=10)
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--chain', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    records = sorted((args.chain / 'blocks').glob('*.blk'))
    assert len(records) == 274 and {int(p.name.split('-')[0]) for p in records} == set(range(274))
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in records}
    owners = addresses(records)
    assert owners
    nodes = [str(args.old.resolve()), str(args.new.resolve())]
    directories = [root / 'old', root / 'new']
    processes, logs, rss = [], [], []
    try:
        for node, directory in zip(nodes, directories):
            shutil.copytree(args.chain / 'blocks', directory / 'blocks')
            if (args.chain / 'mempool').exists():
                shutil.copytree(args.chain / 'mempool', directory / 'mempool')
            log = open(root / (directory.name + '.log'), 'w')
            logs.append(log)
            proc = start(node, directory, log)
            processes.append(proc)
            rss.append(int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(proc.pid)], text=True).strip()))
        checks = [('getblock', str(h)) for h in range(274)] + [('snapshot', '64'), ('mempool',)]
        checks += [(verb, owner) for owner in owners for verb in ('balance', 'utxos')]
        for i, command in enumerate(checks):
            left, right = [cli(n, d, *command) for n, d in zip(nodes, directories)]
            (root / f'{i:03}-old.txt').write_bytes(left)
            (root / f'{i:03}-new.txt').write_bytes(right)
            assert left == right, f'Output differs: {command}'
        for directory in directories:
            assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (directory / 'blocks').glob('*.blk')} == hashes
        assert {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in records} == hashes
        result = {'byte_identical_commands': len(checks), 'heights': '0..273', 'addresses': owners,
                  'old_rss_kib': rss[0], 'new_rss_kib': rss[1], 'block_records_unchanged': 274}
        (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2), flush=True)
        print('ALL DIFFERENTIAL REPLAY CHECKS PASSED', flush=True)
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
        for proc in processes:
            proc.wait(timeout=15)
        for log in logs:
            log.close()


if __name__ == '__main__':
    main()
