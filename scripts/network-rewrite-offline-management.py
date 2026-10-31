"""Hosted-only exact SQLite/HTTP offline authority acceptance receipts."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--suite', choices=['storage', 'sdk'], required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
output = args.output
output.mkdir(parents=True, exist_ok=True)
package, target, count = ('nestlink-storage', ['--lib'], 8) if args.suite == 'storage' else ('nestlink-sdk', ['--test', 'private_services'], 7)
build = ['cargo', 'test', '--locked', '-p', package, *target, '--no-run', '--message-format=json']
receipt = {
    'source_revision': source, 'run_id': os.environ['GITHUB_RUN_ID'],
    'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'workflow': os.environ['GITHUB_WORKFLOW_REF'],
    'runner_environment': os.environ['RUNNER_ENVIRONMENT'], 'runner_os': os.environ['RUNNER_OS'],
    'suite': args.suite,
    'scope': ('Independent private-service online enable/review/reserve/consume/recovery; original shared SQLite budget and actual HTTP/SDK. SDK suite also exercises original direct QUIC/mTLS TCP bytes after physical center disconnect, reconnect, half-close, deadline, byte ceiling, process exit, authenticated revocation and original physical cleanup receipts. No UDP/TLS fallback, resident UI, remote-control or target-platform acceptance claimed.'),
    'cargo_lock_sha256': hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest(),
    'build_command': build, 'passed': False,
}
try:
    with (output / 'build.jsonl').open('w') as stream, (output / 'build.log').open('w') as errors:
        built = subprocess.run(build, stdout=stream, stderr=errors, check=False)
    receipt['build_exit_code'] = built.returncode
    assert built.returncode == 0, 'Build failed; see exact retained diagnostics'
    executables = [entry['executable'] for line in (output / 'build.jsonl').read_text().splitlines()
                   if (entry := json.loads(line)).get('reason') == 'compiler-artifact' and entry.get('executable')]
    assert len(executables) == 1, executables
    executable = pathlib.Path(executables[0])
    inventory = subprocess.check_output([str(executable), 'offline::', '--list'], text=True)
    (output / 'inventory.log').write_text(inventory)
    names = [line.removesuffix(': test') for line in inventory.splitlines() if line.endswith(': test')]
    assert len(names) == count and len(set(names)) == count, names
    execution = [str(executable), 'offline::', '--nocapture', '--test-threads=1', '--color', 'never']
    with (output / 'tests.log').open('w') as stream:
        tested = subprocess.run(execution, stdout=stream, stderr=subprocess.STDOUT, timeout=240, check=False)
    receipt.update(executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), tests=names,
                   execution_command=execution, test_exit_code=tested.returncode)
    assert tested.returncode == 0 and f'{count} passed; 0 failed; 0 ignored' in (output / 'tests.log').read_text()
    receipt['passed'] = True
finally:
    receipt['files'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file()}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
