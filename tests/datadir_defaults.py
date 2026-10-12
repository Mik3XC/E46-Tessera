#!/usr/bin/env python3
"""Exercise default/legacy datadir handling with an isolated HOME and no peers."""
import argparse
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


parser = argparse.ArgumentParser()
parser.add_argument('--node', type=Path, required=True)
args = parser.parse_args()
node = str(args.node.resolve())


def run(env, *words, ok=True, mask=0):
    result = subprocess.run([node, *map(str, words)], env=env, text=True,
                            capture_output=True, timeout=65, umask=mask)
    print('$ e46-node ' + ' '.join(map(str, words)), flush=True)
    print((result.stdout + result.stderr).strip(), flush=True)
    assert (result.returncode == 0) == ok, result
    return result


with tempfile.TemporaryDirectory(prefix='e46-data-', dir='/tmp') as scratch:
    root = Path(scratch)
    env = dict(os.environ)
    # Never inherit a real data or cache location, including on Linux.
    env.pop('XDG_DATA_HOME', None)
    env.pop('XDG_CACHE_HOME', None)
    home = root / 'home'
    home.mkdir()
    env['HOME'] = str(home)
    if sys.platform == 'darwin':
        default = home / 'Library/Application Support/E46Tessera'
        legacy = home / 'Library/Caches/E46Tessera'
    else:
        default = home / '.local/share/E46Tessera'
        legacy = home / '.cache/E46Tessera'

    # A permissive umask must never expose a newly created default directory.
    run(env, 'mempool')
    assert (default / 'blocks').is_dir()
    assert stat.S_IMODE(default.stat().st_mode) == 0o700
    print(f'PASS default {default} created mode {stat.S_IMODE(default.stat().st_mode):04o}', flush=True)
    assert not legacy.exists()

    # Preserve a genuine block store as the legacy fixture; do not synthesize blocks.
    legacy.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(default), str(legacy))
    default.parent.rmdir()
    for existing_default in (False, True):
        if existing_default:
            default.mkdir(parents=True)
        before = sorted(str(p.relative_to(home)) for p in home.rglob('*'))
        result = run(env, 'mempool', ok=False)
        assert 'Legacy block store found' in result.stderr
        assert str(legacy) in result.stderr and str(default) in result.stderr
        assert '--datadir' in result.stderr and 'move the old datadir yourself' in result.stderr
        assert sorted(str(p.relative_to(home)) for p in home.rglob('*')) == before
        assert not (default / 'blocks').exists()
        print('PASS legacy guard creates nothing' + (' (default already exists)' if existing_default else ''), flush=True)

    run(env, '--datadir', legacy, 'mempool')
    explicit = root / 'explicit'
    run(env, '--datadir', explicit, 'mempool', mask=0o022)
    assert (explicit / 'blocks').is_dir()
    assert stat.S_IMODE(explicit.stat().st_mode) == 0o755
    assert not (default / 'blocks').exists()
    print('PASS explicit datadir overrides legacy guard and retains existing permission behavior', flush=True)

    shutil.copytree(legacy / 'blocks', default / 'blocks')
    run(env, 'mempool')
    print('PASS existing new block store takes precedence over legacy store', flush=True)

    if sys.platform != 'darwin':
        env['XDG_DATA_HOME'] = str(root / 'xdg-data')
        xdg_default = Path(env['XDG_DATA_HOME']) / 'E46Tessera'
        result = run(env, 'mempool', ok=False)
        assert str(xdg_default) in result.stderr and str(legacy) in result.stderr
        assert not xdg_default.parent.exists()
        # Keep the old store, but outside any legacy default, to exercise XDG creation.
        archive = root / 'archive'
        shutil.move(str(legacy), str(archive))
        run(env, 'mempool')
        assert (xdg_default / 'blocks').is_dir()
        assert stat.S_IMODE(xdg_default.stat().st_mode) == 0o700
        shutil.rmtree(xdg_default)
        env['XDG_CACHE_HOME'] = str(root / 'xdg-cache')
        custom_legacy = Path(env['XDG_CACHE_HOME']) / 'E46Tessera'
        custom_legacy.parent.mkdir()
        shutil.move(str(archive), str(custom_legacy))
        result = run(env, 'mempool', ok=False)
        assert str(custom_legacy) in result.stderr and str(xdg_default) in result.stderr
        assert not xdg_default.exists()
        print('PASS XDG_DATA_HOME and legacy XDG_CACHE_HOME handling', flush=True)

    env.pop('HOME')
    result = run(env, 'mempool', ok=False)
    assert 'HOME is unset; pass --datadir DIR' in result.stderr
    run(env, '--datadir', explicit, 'mempool')
    print('PASS HOME-unset diagnostic and explicit override', flush=True)

print('ALL DATADIR CHECKS PASSED', flush=True)
