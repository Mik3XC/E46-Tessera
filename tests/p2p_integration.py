#!/usr/bin/env python3
"""Local two-node exercise. No secrets, downloads, or consensus shortcuts.
Optional --chain/--payment consume public historical fixtures supplied by the operator.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--node', type=Path, required=True)
parser.add_argument('--chain', type=Path)
parser.add_argument('--payment', type=Path)
parser.add_argument('--mine-real', action='store_true', help='Also wait up to 30 minutes for a freshly mined block and its relay')
args = parser.parse_args()
node = str(args.node.resolve())
cache = Path.home() / ('Library/Caches/E46Tessera' if os.uname().sysname == 'Darwin' else '.cache/E46Tessera')
cache.mkdir(parents=True, exist_ok=True)
root = Path(tempfile.mkdtemp(prefix='p2p-', dir=cache))
print(f'Exercise files: {root}', flush=True)
processes = []
logs = []


def cli(directory, *words, ok=True):
    proc = subprocess.run([node, '--datadir', str(directory), *map(str, words)], text=True, capture_output=True, timeout=65)
    if ok and proc.returncode:
        raise AssertionError(f'{words[0]} failed: {proc.stderr}')
    if not ok:
        assert proc.returncode, f'{words[0]} unexpectedly succeeded'
        return proc.stderr
    return proc.stdout


def wait_for(fn, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return
        time.sleep(.15)
    raise AssertionError('Timed out waiting for expected node state')


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start(directory, p, remote=None):
    directory.mkdir(parents=True, exist_ok=True)
    log = open(root / f'{directory.name}-{len(logs)}.log', 'w')
    logs.append(log)
    cmd = [node, '--datadir', str(directory), 'serve', '--listen', f'127.0.0.1:{p}']
    if remote:
        cmd += ['--connect', f'127.0.0.1:{remote}']
    proc = subprocess.Popen(cmd, stdout=log, stderr=log)
    processes.append(proc)
    def ready():
        if proc.poll() is not None:
            raise AssertionError(f'Daemon exited: {Path(log.name).read_text()}')
        if not (directory / 'control.sock').exists():
            return False
        result = subprocess.run([node, '--datadir', str(directory), 'status'], text=True, capture_output=True, timeout=65)
        return result.returncode == 0 and 'height ' in result.stdout
    wait_for(ready)
    assert 'height ' in cli(directory, 'status')
    return proc


def height(directory):
    return int(cli(directory, 'status').splitlines()[0].split()[1])


def frame(t, payload=b''):
    return b'E46P' + struct.pack('!II', t, len(payload)) + payload


def exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


def receive(s):
    magic, t, length = struct.unpack('!4sII', exact(s, 12))
    assert magic == b'E46P' and length <= 4_100_032
    return t, exact(s, length)


def connected(p):
    s = socket.create_connection(('127.0.0.1', p), timeout=5)
    s.settimeout(5)
    t, hello = receive(s)
    assert t == 1 and len(hello) == 80
    reply = hello[:40] + os.urandom(8) + hello[48:]
    s.sendall(frame(1, reply))
    return s


def closed(s):
    try:
        while True:
            receive(s)
    except (EOFError, ConnectionResetError, BrokenPipeError):
        return
    raise AssertionError('Expected peer disconnection')


def milestone(text):
    print('PASS ' + text, flush=True)


try:
    guard = root / 'guard'
    guard.mkdir()
    guardfile = guard / 'control.sock'
    guardfile.write_text('operator file: do not delete\n')
    assert 'not our socket' in cli(guard, 'serve', '--listen', f'127.0.0.1:{port()}', ok=False)
    assert guardfile.read_text() == 'operator file: do not delete\n'
    milestone('non-socket control path is rejected and preserved')
    # A datadir whose control-socket path exceeds the OS limit must not break
    # ordinary one-shot commands; only `serve` is refused, with a clear message.
    longdir = root / ('long-' + 'x' * 80) / 'datadir'
    longdir.mkdir(parents=True)
    assert len(str(longdir / 'control.sock')) > 104
    assert cli(longdir, 'mempool').startswith('transactions 0')
    assert 'too long' in cli(longdir, 'serve', '--listen', f'127.0.0.1:{port()}', ok=False)
    milestone('long datadir path: one-shot commands work, serve refuses it clearly')
    a, b = root / 'a', root / 'b'
    pa, pb = port(), port()
    records = {}
    if args.chain:
        assert args.payment, '--payment is required with --chain'
        for record in (args.chain / 'blocks').glob('*.blk'):
            records[int(record.name.split('-')[0])] = record
        assert all(h in records for h in range(270)), 'Need canonical blocks 0..269'
        (a / 'blocks').mkdir(parents=True)
        for h in range(268):
            shutil.copy2(records[h], a / 'blocks' / records[h].name)
    aproc = start(a, pa)
    bproc = start(b, pb, pa)
    target = 267 if records else 0
    wait_for(lambda: height(b) == target, 180)
    assert json.loads(cli(b, 'snapshot', 1))['tipId'] == json.loads(cli(a, 'snapshot', 1))['tipId']
    assert json.loads(cli(b, 'snapshot', 1))['p2pEnabled'] is True
    milestone(f'genesis-to-height-{target} sync; same validated tip; explorer reads daemon')
    assert 'Another node' in cli(a, 'serve', '--listen', f'127.0.0.1:{port()}', ok=False)
    assert 'Another node' in cli(a, 'rebuild', ok=False)
    milestone('exclusive datadir ownership')
    for label, offset in [('version', 3), ('network', 7), ('genesis', 8)]:
        with socket.create_connection(('127.0.0.1', pb), timeout=5) as s:
            s.settimeout(5)
            _, hello = receive(s)
            bad = bytearray(hello[:40] + os.urandom(8) + hello[48:])
            bad[offset] ^= 2
            s.sendall(frame(1, bad))
            closed(s)
        milestone(label + ' mismatch rejected')
    with socket.create_connection(('127.0.0.1', pb), timeout=5) as s:
        s.settimeout(5)
        receive(s)
        s.sendall(b'E46P' + struct.pack('!II', 1, 0xffffffff))
        closed(s)
    with connected(pb) as s:
        s.sendall(frame(100, b'stop\n'))
        closed(s)
    milestone('oversized frames and remote control commands rejected')
    held = []
    try:
        wait_for(lambda: 'peers 1\n' in cli(b, 'status'))
        for _ in range(7):
            held.append(connected(pb))
        wait_for(lambda: 'peers 8\n' in cli(b, 'status'))
        with socket.create_connection(('127.0.0.1', pb), timeout=5) as overflow:
            overflow.settimeout(5)
            closed(overflow)
        assert 'height ' in cli(b, 'status')
    finally:
        for s in held:
            s.close()
    milestone('eight-peer cap enforced while private control remains responsive')
    with socket.create_connection(('127.0.0.1', pb), timeout=5) as silent:
        silent.settimeout(15)
        receive(silent)
        closed(silent)
    milestone('silent peer handshake deadline enforced')
    if records:
        with connected(pb) as s:
            # Only send BLOCK after the node asks us for the next block.
            while receive(s)[0] != 2:
                pass
            bad = bytearray(records[268].read_bytes())
            bad[-1] ^= 1
            s.sendall(frame(3, bad))
            closed(s)
        assert height(b) == 267
        bad_record = root / 'bad-checkpoint.blk'
        bad = bytearray(records[268].read_bytes())
        bad[8 + 112] ^= 1  # Header nonce changes the pinned height-268 ID.
        bad_record.write_bytes(bad)
        assert 'checkpoint' in cli(b, 'import', bad_record, ok=False).lower()
        milestone('invalid block over TCP and checkpoint mismatch rejected; tip unchanged')
        payment = bytes.fromhex(args.payment.read_text().strip())
        txid = bytes.fromhex('df6fe5245b8326b0486b1727481604414dc8928e3300c7df78629cecdb18d8ab')
        with connected(pb) as s:
            s.sendall(frame(5, txid))
            while True:
                typ, data = receive(s)
                if typ == 2:
                    s.sendall(frame(8))
                if typ == 6:
                    assert data == txid
                    bad = bytearray(payment)
                    bad[-1] ^= 1
                    s.sendall(frame(7, txid + bad))
                    break
            closed(s)
        assert cli(b, 'mempool').startswith('transactions 0')
        milestone('bad transaction signature rejected over TCP')
        assert 'ACCEPTED' in cli(a, 'submit', payment.hex())
        wait_for(lambda: txid.hex() in cli(b, 'mempool'))
        milestone('signed payment accepted on A and relayed to B')
        catchup = root / 'catchup'
        catchproc = start(catchup, port(), pa)
        wait_for(lambda: height(catchup) == 267 and txid.hex() in cli(catchup, 'mempool'), 180)
        cli(catchup, 'stop')
        catchproc.wait(timeout=10)
        milestone('new peer defers pending payment validation until funding chain is synchronized')
        bproc.kill()
        bproc.wait(timeout=10)
        bproc = start(b, pb, pa)
        assert txid.hex() in cli(b, 'mempool')
        assert height(b) == 267
        milestone('abrupt restart recovers chain and pending signed payment')
        assert 'IMPORTED 268' in cli(a, 'import', records[268])
        wait_for(lambda: height(b) == 268)
        for directory in (a, b):
            assert cli(directory, 'mempool').startswith('transactions 0')
            assert txid.hex() in cli(directory, 'getblock', 268)
            assert cli(directory, 'balance', 'te461q8nzqu470z8tgnjwfluz7wcq37726e0mqza7rrd87r0ln46qgvtfqr4ut70').strip() == '100000000'
        milestone('accepted block relayed; payment confirmed; both mempools cleaned; recipient balances agree')
        invalid_pow = root / 'bad-pow.blk'
        bad = bytearray(records[269].read_bytes())
        bad[120:128] = bytes(8)
        invalid_pow.write_bytes(bad)
        assert 'proof of work' in cli(b, 'import', invalid_pow, ok=False).lower()
        assert height(b) == 268
        milestone('invalid proof of work rejected beyond checkpoint')
        assert 'IMPORTED 269' in cli(a, 'import', records[269])
        wait_for(lambda: height(b) == 269)
        cli(b, 'submit', payment.hex(), ok=False)
        milestone('next block synchronized and spent payment rejected')
    # Start and stop real background header work without changing consensus or waiting for luck.
    mining = cli(a, 'mine', 1, 'te461q3l06pexsjjx2hngmd6z6pjfgpthyf879ez78efxnek9we63uqt7qjc5xfp')
    assert mining.startswith('MINING 1')
    assert 'height ' in cli(a, 'status')
    assert 'MINING STOPPED' in cli(a, 'stop-mining')
    milestone('mining runs asynchronously; control remains responsive; cancellation works')
    cli(b, 'stop')
    bproc.wait(timeout=10)
    before = json.loads(cli(b, 'snapshot', 1))
    assert 'REBUILT height ' in cli(b, 'rebuild')
    after = json.loads(cli(b, 'snapshot', 1))
    assert before['height'] == after['height'] and before['tipId'] == after['tipId']
    milestone('full stored-block replay rebuilds identical chain state')
    if records:
        missing = root / 'missing'
        shutil.copytree(b / 'blocks', missing / 'blocks')
        (missing / 'blocks' / records[154].name).unlink()
        cli(missing, 'rebuild', ok=False)
        corrupt = root / 'corrupt'
        shutil.copytree(b / 'blocks', corrupt / 'blocks')
        path = corrupt / 'blocks' / records[268].name
        original = path.read_bytes()
        path.write_bytes(original[:-1])
        cli(corrupt, 'rebuild', ok=False)
        assert path.read_bytes() == original[:-1]
        milestone('missing/corrupt block stores fail rebuild without deleting evidence')
        # Rebuild a new datadir entirely from its peer, independent of the copied store.
        fresh = root / 'fresh'
        freshproc = start(fresh, port(), pa)
        wait_for(lambda: height(fresh) == 269, 180)
        assert json.loads(cli(fresh, 'snapshot', 1))['tipId'] == after['tipId']
        cli(fresh, 'stop')
        freshproc.wait(timeout=10)
        milestone('fresh datadir reconstructs the complete 269-block chain from its peer')
    if args.mine_real:
        bproc = start(b, pb, pa)
        initial = height(a)
        assert cli(a, 'mine', 1, 'te461q3l06pexsjjx2hngmd6z6pjfgpthyf879ez78efxnek9we63uqt7qjc5xfp').startswith('MINING 1')
        print('Mining a fresh valid block at the unchanged consensus target...', flush=True)
        wait_for(lambda: height(a) == initial + 1 and height(b) == initial + 1, 1800)
        assert json.loads(cli(a, 'snapshot', 1))['tipId'] == json.loads(cli(b, 'snapshot', 1))['tipId']
        milestone('fresh proof of work mined by daemon A, validated and relayed to B')
        cli(b, 'stop')
        bproc.wait(timeout=10)
    cli(a, 'stop')
    aproc.wait(timeout=10)
    print('ALL REQUESTED EXERCISE CHECKS PASSED', flush=True)
finally:
    for proc in processes:
        if proc.poll() is None:
            proc.terminate()
    for proc in processes:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    for log in logs:
        log.close()
