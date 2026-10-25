"""GitHub manifest writer only; never executes either diagnostic/preparation EXE."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

EXTRA = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo/config.toml',
         'docs/refactor/native-codecs.lock.json', '.github/workflows/rust-core.yml',
         'scripts/refactor-windows-normal-user.py', 'scripts/refactor-preparation-artifact.py']
COMMANDS = [
    'cargo build --locked --release -p nestlink-protocol --example probe-format-canonical',
    'cargo build --locked --release -p nestlink-media-codec --example windows-cpu-direction-probe',
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    assert os.environ['GITHUB_ACTIONS'] == 'true' and os.environ['RUNNER_OS'] == 'Windows'
    assert os.environ['GITHUB_REPOSITORY'] == 'ZHanry/NestLink'
    source = os.environ['GITHUB_SHA']
    assert re.fullmatch('[0-9a-f]{40}', source)
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == source
    assert not subprocess.check_output(['git', 'status', '--porcelain']).strip()
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        assert re.fullmatch('[1-9][0-9]*', os.environ[key])
    names = subprocess.check_output(['git', 'ls-files', '-z', '--',
                                    'crates/protocol', 'crates/media-codec', 'protocol-spec']).decode('utf-8').split('\0')[:-1]
    names = sorted(set(names + EXTRA))
    output = Path(os.environ['RUNNER_TEMP']) / 'nestlink-media-preparation-tools'
    output.mkdir()
    target = Path(os.environ.get('CARGO_TARGET_DIR') or 'target')
    if os.environ.get('CARGO_BUILD_TARGET'):
        target /= os.environ['CARGO_BUILD_TARGET']
    binaries = []
    for name in ('probe-format-canonical.exe', 'windows-cpu-direction-probe.exe'):
        blob = (target / 'release/examples' / name).read_bytes()
        (output / name).write_bytes(blob)
        binaries.append(dict(filename=name, bytes=len(blob), sha256=sha(blob)))
    manifest = dict(schema=1, purpose='format-preparation-and-independent-cpu-qualification-only',
                    source_revision=source, repository=os.environ['GITHUB_REPOSITORY'],
                    run_id=os.environ['GITHUB_RUN_ID'], run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],
                    workflow=os.environ['GITHUB_WORKFLOW'], build_profile='release',
                    build_commands=COMMANDS, build_identity='verified-medium-non-admin-token',
                    executed_on_github=False, product_negotiation_enabled=False,
                    binaries=binaries, source_hash_contract='git-blob-bytes-v1',
                    source_files=[dict(path=n, sha256=sha(subprocess.check_output(
                        ['git', 'show', source + ':' + n]))) for n in names])
    (output / 'preparation-build.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
