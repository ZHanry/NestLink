"""Derive bounded RC2 SQLite/rustix security updates on hosted Actions only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', choices=('product', 'browser-native-fixture', 'security-fuzz'), required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    assert os.environ.get('GITHUB_REPOSITORY') == 'ZHanry/NestLink'
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    assert source == args.source == os.environ['GITHUB_SHA']
    assert not subprocess.check_output(['git', 'status', '--porcelain=v1', '--untracked-files=all'], cwd=root)
    assert tomllib.loads((root/'Cargo.toml').read_text())['workspace']['dependencies']['rusqlite'] == {
        'version': '=0.41.0', 'default-features': False,
        'features': ['cache', 'bundled', 'backup', 'serialize', 'fallible_uint']}
    manifest = root/{'product': 'Cargo.toml', 'browser-native-fixture': 'scripts/fixtures/browser-native-host/Cargo.toml',
                     'security-fuzz': 'tests/security/fuzz/Cargo.toml'}[args.scope]
    lock = manifest.with_name('Cargo.lock')
    before = lock.read_bytes()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'before.lock').write_bytes(before)
    receipt = {'source_revision': source, 'scope': args.scope, 'run_id': os.environ['GITHUB_RUN_ID'],
               'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'commands': [], 'passed': False,
               'product_compilation_performed': False}

    def execute(name, command):
        with (args.output/(name+'.log')).open('wb') as stream:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
        receipt['commands'].append({'name': name, 'argv': command, 'return_code': result.returncode})
        assert result.returncode == 0, name

    try:
        if args.scope != 'security-fuzz':
            execute('sqlite-update', ['cargo','update','--manifest-path',str(manifest),'-p','rusqlite','--precise','0.41.0'])
        # Existing pre-1.x rustix is unaffected by this advisory and stays locked.
        current = tomllib.loads(lock.read_text())['package']
        selected = [p for p in current if p['name']=='rustix' and p['version'].startswith('1.')]
        assert len(selected) == 1
        execute('rustix-update', ['cargo','update','--manifest-path',str(manifest),'-p',
                                'rustix@'+selected[0]['version'],'--precise','1.1.6'])
        execute('locked-resolver', ['cargo','metadata','--manifest-path',str(manifest),'--locked','--format-version','1'])
        after = lock.read_bytes()
        original = {(p['name'],p['version'],p.get('source','')):p for p in tomllib.loads(before.decode())['package']}
        derived = {(p['name'],p['version'],p.get('source','')):p for p in tomllib.loads(after.decode())['package']}
        changed = [key for key in original.keys() | derived.keys() if original.get(key) != derived.get(key)]
        receipt['changed_packages'] = [{'name':key[0],'version':key[1],'source':key[2]} for key in sorted(changed)]
        # Review the exact diff before importing. No write-back, commit or compilation occurs here.
        receipt['review_required'] = True
        receipt['before_sha256'] = hashlib.sha256(before).hexdigest()
        receipt['after_sha256'] = hashlib.sha256(after).hexdigest()
        assert all(p['version'] == '1.1.6' for p in derived.values() if p['name']=='rustix' and p['version'].startswith('1.'))
        if args.scope != 'security-fuzz':
            assert any(p['name']=='rusqlite' and p['version']=='0.41.0' for p in derived.values())
            assert all(p['version'].startswith('0.39.') for p in derived.values() if p['name']=='libsqlite3-sys')
        receipt['passed'] = True
    finally:
        (args.output/'Cargo.lock').write_bytes(lock.read_bytes())
        diff = subprocess.check_output(['git','diff','--',str(lock.relative_to(root))],cwd=root)
        (args.output/'derivation.diff').write_bytes(diff)
        (args.output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__ == '__main__':
    main()
