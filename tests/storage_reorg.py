#!/usr/bin/env python3
"""Run real-PoW branch fixtures, then compare rollback CLI output after restart."""
import argparse
import json
from pathlib import Path
import subprocess
from storage_replay import addresses, cli

parser = argparse.ArgumentParser()
parser.add_argument('--tool', type=Path, required=True)
parser.add_argument('--node', type=Path, required=True)
parser.add_argument('--fixtures', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
node = str(args.node.resolve())
subprocess.run([str(args.tool.resolve()), 'exercise', str(args.fixtures.resolve()), str(args.output.resolve())], check=True, timeout=180)
root = args.output.resolve()
owners = addresses(sorted(args.fixtures.glob('*.blk')))
checks = [('snapshot', '64'), ('mempool',)] + [(verb, a) for a in owners for verb in ('balance', 'utxos')]
for i, words in enumerate(checks):
    before = cli(node, root / 'baseline', *words)
    after = cli(node, root / 'invalid', *words)
    (root / f'rollback-{i}-before.txt').write_bytes(before)
    (root / f'rollback-{i}-after.txt').write_bytes(after)
    assert before == after, words
for name, expected in (('one', 2), ('deep', 3), ('invalid', 2)):
    snap = json.loads(cli(node, root / name, 'snapshot', '64'))
    assert snap['height'] == expected
    assert 'REBUILT height ' in cli(node, root / name, 'rebuild').decode()
    assert snap == json.loads(cli(node, root / name, 'snapshot', '64'))
print(f'PASS rollback: {len(checks)} byte-identical snapshot/mempool/balance/utxos outputs after restart')
print('PASS all branch stores reproduce identical snapshots after explicit rebuild')
print('ALL STORAGE REORG CHECKS PASSED')
