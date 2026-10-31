"""Hosted-only exact SQLite/HTTP offline authority acceptance receipts."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--suite', choices=['storage', 'sdk', 'daemon', 'remote-identity', 'remote-session', 'remote-storage', 'remote-sdk', 'remote-offline'], required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
output = args.output
output.mkdir(parents=True, exist_ok=True)
package, target, count = {
    'storage': ('nestlink-storage', ['--lib'], 8),
    'sdk': ('nestlink-sdk', ['--test', 'private_services'], 7),
    'daemon': ('nestlink-daemon', ['--bin', 'nestlink-daemon'], 1),
    'remote-identity': ('nestlink-identity', ['--lib'], 3),
    'remote-session': ('nestlink-session', ['--test', 'authorization'], 2),
    'remote-storage': ('nestlink-storage', ['--test', 'control'], 5),
    'remote-sdk': ('nestlink-sdk', ['--test', 'end_to_end'], 1),
    'remote-offline': ('nestlink-sdk', ['--test', 'offline_remote'], 1),
}[args.suite]
test_filter = 'offline_remote_' if args.suite == 'remote-offline' else ('remote_budget' if args.suite.startswith('remote-') else 'offline::')
build = ['cargo', 'test', '--locked', '-p', package, *target, '--no-run', '--message-format=json']
receipt = {
    'source_revision': source, 'run_id': os.environ['GITHUB_RUN_ID'],
    'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'workflow': os.environ['GITHUB_WORKFLOW_REF'],
    'runner_environment': os.environ['RUNNER_ENVIRONMENT'], 'runner_os': os.environ['RUNNER_OS'],
    'suite': args.suite,
    'scope': ('Independent private-service online enable/review/reserve/consume/recovery; original shared SQLite budget and actual HTTP/SDK. SDK also exercises direct QUIC/mTLS TCP bytes, disconnection, reconnect, half-close, deadline, byte ceiling, original ephemeral process proof, revocation and physical cleanup. Daemon suite tests its actual resident lifecycle guard against protected login/identity changes and original installation maintenance; it does not claim protected login restoration or interactive multi-process acceptance. No UDP/TLS fallback, remote-control or target-platform acceptance claimed.'),
    'cargo_lock_sha256': hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest(),
    'build_command': build, 'passed': False,
}
try:
    if args.suite.startswith('remote-'):
        receipt['scope'] = 'Original remote cumulative budget reservation, strict signed scope, retained Session meter and actual HTTP/SDK/QUIC online business accounting. Storage additionally exercises independent finite offline remote draft, atomic second approval against original online totals, one-use consume, revoke without refund and original short online expiry. Remote offline carrier and target acceptance are excluded.'
    if args.suite == 'remote-offline':
        receipt['scope'] = 'Actual two-account HTTP/SDK offline draft/approval/one-use consume followed by physical management listener stop, original online permit expiry and fresh process proof plus original QUIC Session/business queues; subset permission, original meter, process stop and physical UDP release. No complete native media/input/file OS adapters, TLS fallback, UI or target acceptance claim.'
    with (output / 'build.jsonl').open('w') as stream, (output / 'build.log').open('w') as errors:
        built = subprocess.run(build, stdout=stream, stderr=errors, check=False)
    receipt['build_exit_code'] = built.returncode
    assert built.returncode == 0, 'Build failed; see exact retained diagnostics'
    executables = [entry['executable'] for line in (output / 'build.jsonl').read_text().splitlines()
                   if (entry := json.loads(line)).get('reason') == 'compiler-artifact' and entry.get('executable')]
    assert len(executables) == 1, executables
    executable = pathlib.Path(executables[0])
    inventory = subprocess.check_output([str(executable), test_filter, '--list'], text=True)
    (output / 'inventory.log').write_text(inventory)
    names = [line.removesuffix(': test') for line in inventory.splitlines() if line.endswith(': test')]
    assert len(names) == count and len(set(names)) == count, names
    execution = [str(executable), test_filter, '--nocapture', '--test-threads=1', '--color', 'never']
    with (output / 'tests.log').open('w') as stream:
        tested = subprocess.run(execution, stdout=stream, stderr=subprocess.STDOUT, timeout=240, check=False)
    receipt.update(executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), tests=names,
                   execution_command=execution, test_exit_code=tested.returncode)
    assert tested.returncode == 0 and f'{count} passed; 0 failed; 0 ignored' in (output / 'tests.log').read_text()
    receipt['passed'] = True
finally:
    receipt['files'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file()}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
