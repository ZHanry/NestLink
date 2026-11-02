"""GitHub-hosted-only real kernel tc impairment on the exact original QUIC pair."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=pathlib.Path, required=True)
args = parser.parse_args()
assert os.environ['RUNNER_ENVIRONMENT'] == 'github-hosted'
assert os.geteuid() != 0, 'build and business execution must use the ordinary hosted runner token'
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=False)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
assert source == os.environ['GITHUB_SHA']
receipt = {
    'source_revision': source, 'run_id': os.environ['GITHUB_RUN_ID'],
    'run_attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'workflow': os.environ['GITHUB_WORKFLOW_REF'],
    'runner_environment': os.environ['RUNNER_ENVIRONMENT'], 'runner_os': os.environ['RUNNER_OS'],
    'cargo_lock_sha256': hashlib.sha256(pathlib.Path('Cargo.lock').read_bytes()).hexdigest(),
    'scope': 'Real loopback kernel QUIC/mTLS, tc 1percent random loss and 20-to-5Mbps per-direction rate, original VP8 sender/receiver, original FileReadServer/client with actual disk file and SHA verification, original InputController dispatch observation. Capture is synthetic moving pixels; input observer has no OS effects. No OS input-to-display, Windows exact H264/Core, physical GPU, NAT, whole AC53 or target acceptance claim.',
    'passed': False, 'commands': [], 'whole_task_passed': False,
    'execution_uid': os.geteuid(),
    'impairment_semantics': 'Kernel netem configured random loss1percent, not an independently measured per-UDP-datagram loss probability. Loopback GSO/GRO state and exact qdisc/class counters are retained.',
}
owned_qdisc = False
process = None

def command(argv):
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    text = result.stdout.decode(errors='replace')
    receipt['commands'].append({'argv': argv, 'return_code': result.returncode, 'output': text})
    assert result.returncode == 0, (argv, text)
    return text


def tc(*arguments):
    # Only the owned qdisc mutation requires root. Compilation, file I/O and
    # the actual original product owners always retain the ordinary UID.
    return command(['sudo', '--non-interactive', 'tc', *arguments])

def wait_file(name, seconds):
    end = time.monotonic() + seconds
    path = output / name
    while not path.exists():
        assert process.poll() is None, f'original test ended before {name}; see tests.log'
        assert time.monotonic() < end, f'original test did not reach {name}'
        time.sleep(0.01)
    return path

try:
    receipt['tc_version'] = command(['tc', '-Version'])
    receipt['loopback_offloads'] = command(['ethtool', '--show-offload', 'lo'])
    initial = json.loads(tc('-json', 'qdisc', 'show', 'dev', 'lo'))
    assert all(item['kind'] == 'noqueue' for item in initial), 'refuse replacing an unrelated loopback qdisc'
    with (output / 'build.jsonl').open('w') as events, (output / 'build.log').open('w') as errors:
        build = ['cargo', 'test', '--locked', '--release', '-p', 'nestlink-media-session', '--lib', '--features', 'network-impairment-lab', '--no-run', '--message-format=json']
        built = subprocess.run(build, stdout=events, stderr=errors, check=False)
    receipt['build_command'] = build
    receipt['build_profile'] = 'release'
    receipt['debug_assertions'] = False
    receipt['performance_profile_reason'] = 'Measure original production optimized codec/transport scheduling; default debug codec CPU pressure may lower actual traffic below the intended physical5Mbps step. Original geometry, authority, load and all acceptance gates remain unchanged.'
    receipt['build_exit_code'] = built.returncode
    assert built.returncode == 0, 'see retained build.jsonl and build.log'
    executables = [entry['executable'] for line in (output / 'build.jsonl').read_text().splitlines()
                   if (entry := json.loads(line)).get('reason') == 'compiler-artifact' and entry.get('executable')]
    assert len(executables) == 1
    executable = pathlib.Path(executables[0])
    receipt['executable_sha256'] = hashlib.sha256(executable.read_bytes()).hexdigest()
    test = 'tests::impairment::actual_tc_step_original_vp8_files_and_input'
    inventory = subprocess.check_output([str(executable), test, '--list'], text=True)
    (output / 'inventory.log').write_text(inventory)
    assert inventory.count(': test') == 1 and test + ': test' in inventory
    env = os.environ.copy()
    env['NESTLINK_MEDIA_IMPAIRMENT_DIR'] = str(output)
    with (output / 'tests.log').open('w') as log:
        execution = [str(executable), test, '--exact', '--nocapture', '--test-threads=1', '--color', 'never']
        receipt['execution_command'] = execution
        process = subprocess.Popen(execution, stdout=log, stderr=subprocess.STDOUT, env=env)
        pair = json.loads(wait_file('ready.json', 10).read_text())
        ports = [pair['host_port'], pair['controller_port']]
        assert len(set(ports)) == 2 and all(0 < port <= 65535 for port in ports)
        receipt['original_pair'] = pair
        tc('qdisc', 'add', 'dev', 'lo', 'root', 'handle', '1:', 'htb', 'default', '30')
        owned_qdisc = True
        tc('class', 'add', 'dev', 'lo', 'parent', '1:', 'classid', '1:1', 'htb', 'rate', '10000mbit')
        for index, port in enumerate(ports, 1):
            band = str(index * 10)
            tc('class', 'add', 'dev', 'lo', 'parent', '1:1', 'classid', '1:' + band, 'htb', 'rate', '20mbit', 'ceil', '20mbit')
            tc('qdisc', 'add', 'dev', 'lo', 'parent', '1:' + band, 'handle', band + ':', 'netem', 'loss', '1%', 'limit', '1024')
            tc('qdisc', 'add', 'dev', 'lo', 'parent', band + ':1', 'handle', band + '0:', 'fq_codel', 'target', '5ms', 'interval', '100ms', 'limit', '1024')
            tc('filter', 'add', 'dev', 'lo', 'protocol', 'ip', 'parent', '1:', 'prio', str(index), 'flower', 'ip_proto', 'udp', 'src_ip', '127.0.0.1', 'dst_ip', '127.0.0.1', 'dst_port', str(port), 'classid', '1:' + band)
        tc('class', 'add', 'dev', 'lo', 'parent', '1:1', 'classid', '1:30', 'htb', 'rate', '10000mbit')
        (output / 'configured').write_text('exact pair20Mbps each direction loss1percent\n')
        wait_file('step-request', 20)
        receipt['step_start_unix_ns'] = time.time_ns()
        receipt['class_before_step'] = tc('-statistics', '-json', 'class', 'show', 'dev', 'lo')
        for band in ('10', '20'):
            tc('class', 'change', 'dev', 'lo', 'parent', '1:1', 'classid', '1:' + band, 'htb', 'rate', '5mbit', 'ceil', '5mbit')
        receipt['step_complete_unix_ns'] = time.time_ns()
        (output / 'stepped').write_text('actual tc class changes completed\n')
        process.wait(timeout=50)
        receipt['test_exit_code'] = process.returncode
    receipt['class_final'] = tc('-statistics', '-json', 'class', 'show', 'dev', 'lo')
    receipt['qdisc_final'] = tc('-statistics', '-json', 'qdisc', 'show', 'dev', 'lo')
    assert process.returncode == 0 and '1 passed; 0 failed; 0 ignored' in (output / 'tests.log').read_text()
    measured = json.loads((output / 'measurement.json').read_text())
    receipt['measurement'] = measured
    elapsed_ns = measured['downshift_unix_ns'] - receipt['step_start_unix_ns']
    assert 0 <= elapsed_ns <= 2_000_000_000, 'physical step to actual budget change exceeds original2s'
    receipt['physical_step_to_downshift_ms'] = elapsed_ns / 1_000_000
    receipt['passed'] = True
finally:
    original_failure = sys.exc_info()[1]
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    try:
        if owned_qdisc:
            current = json.loads(tc('-statistics', '-json', 'qdisc', 'show', 'dev', 'lo'))
            receipt['qdisc_before_cleanup'] = current
            assert any(item.get('root') and item.get('handle') == '1:' and item['kind'] == 'htb' for item in current), 'original qdisc owner changed'
            tc('qdisc', 'del', 'dev', 'lo', 'root', 'handle', '1:')
            receipt['owned_qdisc_removed'] = True
    except BaseException as error:
        receipt['passed'] = False
        receipt['cleanup_failure'] = repr(error)
        raise
    finally:
        receipt['original_failure'] = repr(original_failure) if original_failure else None
        receipt['files'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(output.iterdir()) if path.is_file()}
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
