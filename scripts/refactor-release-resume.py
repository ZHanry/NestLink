"""Resume observed Release bytes with bounded ranges and full SHA256 verification."""
import argparse, datetime, hashlib, importlib.util, json, os, pathlib, re, shutil, subprocess, threading, uuid
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('archive', root / 'scripts/refactor-release-archive.py')
archive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archive)
CHUNK = 8 * 1024 * 1024

def range_headers(stream, start, end, total):
    budget = 0
    headers = {}
    line = stream.readline(4097)
    budget += len(line)
    if len(line) > 4096 or not re.fullmatch(b'HTTP/\\S+ 206[^\\r\\n]*\\r?\\n', line):
        raise ValueError('range HTTP status is not 206')
    for _ in range(128):
        line = stream.readline(4097)
        budget += len(line)
        if len(line) > 4096 or budget > 65536 or (not line):
            raise ValueError('range headers are truncated or too large')
        if line in (b'\n', b'\r\n'):
            break
        key, sep, value = line.partition(b':')
        if not sep:
            raise ValueError('range header malformed')
        key = key.strip().lower()
        if key in headers:
            raise ValueError('duplicate range header')
        headers[key] = value.strip()
    else:
        raise ValueError('range headers exceed count bound')
    match = re.fullmatch(b'bytes ([0-9]+)-([0-9]+)/([0-9]+)', headers.get(b'content-range', b''))
    if not match or tuple(map(int, match.groups())) != (start, end, total):
        raise ValueError('range offset/length/total differs from request')
    if b'content-length' in headers and headers[b'content-length'] != str(end - start + 1).encode():
        raise ValueError('range content length differs')
    if headers.get(b'content-encoding', b'identity') != b'identity':
        raise ValueError('encoded ranges cannot be appended')
    return {'start': start, 'end': end, 'total': total, 'http_status': 206}

def download_range(repository, asset, start, end, destination):
    stderr = destination.with_suffix(destination.suffix + '.stderr')
    command = ['gh', 'api', '--hostname', 'github.com', '--method', 'GET', '--include', '-H', 'Accept: application/octet-stream', '-H', f'Range: bytes={start}-{end}', f"repos/{repository}/releases/assets/{asset['asset_id']}"]
    with stderr.open('xb') as errors:
        process = subprocess.Popen(command, env=archive.ENV, stdout=subprocess.PIPE, stderr=errors, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        timer = threading.Timer(300, process.kill)
        timer.start()
        try:
            headers = range_headers(process.stdout, start, end, asset['bytes'])
            remaining = end - start + 1
            with destination.open('xb') as output:
                while remaining:
                    data = process.stdout.read(min(512 * 1024, remaining))
                    if not data:
                        raise ValueError('range body ended early')
                    output.write(data)
                    remaining -= len(data)
                if process.stdout.read(1):
                    raise ValueError('range body exceeds requested length')
                output.flush()
                os.fsync(output.fileno())
            if process.wait() != 0:
                raise ValueError('range process failed after response')
            headers['sha256'] = archive.digest(destination)
            return headers
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()

def resume(base, component, asset, partial=None, inventory_sha256=None, inventory_asset_count=None):
    base = base.resolve()
    target = archive.asset_path(base, component, asset)
    target.parent.mkdir(parents=True, exist_ok=True)
    repository = archive.IDENTITIES[component][0]
    run = uuid.uuid4().hex
    temporary = target.with_name(target.name + '.resume-' + run + '.part')
    report_path = base / f"range-resume-{asset['asset_id']}-{run}.json"
    report = {'asset_id': asset['asset_id'], 'component': component, 'repository': repository, 'bytes': asset['bytes'], 'sha256': asset['github_sha256'], 'verified': False, 'source_inventory_sha256': inventory_sha256, 'source_script_sha256': archive.digest(pathlib.Path(__file__)), 'base_archive_script_sha256': archive.digest(root / 'scripts/refactor-release-archive.py'), 'ranges': [], 'selected_asset_count': 1, 'inventory_asset_count': inventory_asset_count, 'all_inventory_bytes_verified': False, 'durable_remote_archive_uploaded': False, 'finalization_ready': False}
    try:
        report['metadata_before'] = archive.metadata(repository, asset)
        if target.exists():
            archive.verify_bytes(target, asset)
            report['method'] = 'reverified_existing_blob'
            report['verified'] = True
        else:
            prefix = 0
            if partial is not None:
                partial = partial.resolve()
                if partial.parent != target.parent or not re.fullmatch(re.escape(target.name) + '(?:\\.[0-9a-f]{32}|\\.resume-[0-9a-f]{32})\\.part', partial.name):
                    raise ValueError('partial must be the fixed asset original exclusive temporary file')
                before = partial.stat()
                prefix = before.st_size
                if prefix > asset['bytes']:
                    raise ValueError('partial exceeds current asset size')
                report['prefix_sha256'] = archive.digest(partial)
                if (partial.stat().st_size, partial.stat().st_mtime_ns, partial.stat().st_ino) != (before.st_size, before.st_mtime_ns, before.st_ino):
                    raise ValueError('partial changed during inspection')
                report['original_partial'] = partial.relative_to(base).as_posix()
            if shutil.disk_usage(base).free < 2 * asset['bytes'] + CHUNK + 2 * 1024 ** 3:
                raise ValueError('range resume requires assembly and retained chunks plus 2 GiB reserve')
            with temporary.open('xb') as output:
                if partial is not None:
                    with partial.open('rb') as source:
                        shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                    if (partial.stat().st_size, partial.stat().st_mtime_ns, partial.stat().st_ino) != (before.st_size, before.st_mtime_ns, before.st_ino) or temporary.stat().st_size != prefix:
                        raise ValueError('original partial changed while copying')
                output.flush()
                os.fsync(output.fileno())
            position = prefix
            while position < asset['bytes']:
                end = min(asset['bytes'] - 1, position + CHUNK - 1)
                chunk = temporary.with_name(temporary.name + f'.{position}.range')
                result = download_range(repository, asset, position, end, chunk)
                with temporary.open('ab') as output, chunk.open('rb') as source:
                    if temporary.stat().st_size != position:
                        raise ValueError('assembly length changed')
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                position = end + 1
                report['ranges'].append(result)
                report['assembled_bytes'] = position
                archive.atomic_json(report_path, report)
                print(f"{asset['asset_id']}: {position}/{asset['bytes']} assembled", flush=True)
            archive.verify_bytes(temporary, asset)
            report['metadata_after'] = archive.metadata(repository, asset)
            if target.exists():
                raise ValueError('another writer created target; refusing overwrite')
            os.link(temporary, target)
            temporary.unlink()
            archive.verify_bytes(target, asset)
            report['verified'] = True
            report['method'] = 'independent_copy_of_original_partial_and_bounded_ranges'
        report['archive_path'] = target.relative_to(base).as_posix()
    except Exception as e:
        report['error_type'] = type(e).__name__
        report['error'] = str(e) if not isinstance(e, OSError) else 'filesystem failure; private paths omitted'
        if temporary.exists():
            report['retained_partial'] = temporary.relative_to(base).as_posix()
    report['completed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    archive.atomic_json(report_path, report)
    print(json.dumps({'report': str(report_path), 'verified': report['verified'], 'error_type': report.get('error_type'), 'error': report.get('error')}), flush=True)
    return report
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=pathlib.Path, required=True)
    parser.add_argument('--archive-root', type=pathlib.Path, required=True)
    parser.add_argument('--asset-id', type=int, required=True)
    parser.add_argument('--partial', type=pathlib.Path)
    args = parser.parse_args()
    inventory_bytes = args.inventory.resolve().read_bytes()
    inventory_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    inventory_assets = archive.inventory_assets(json.loads(inventory_bytes))
    matches = [(c, a) for c, a in inventory_assets if a['asset_id'] == args.asset_id]
    if len(matches) != 1:
        parser.error('asset absent from fixed inventory')
    c, a = matches[0]
    args.archive_root.mkdir(parents=True, exist_ok=True)
    snapshot = args.archive_root.resolve() / f'inventory-{inventory_sha256}.json'
    if snapshot.exists():
        if archive.digest(snapshot) != inventory_sha256:
            parser.error('saved inventory snapshot changed')
    else:
        with snapshot.open('xb') as output:
            output.write(inventory_bytes)
            output.flush()
            os.fsync(output.fileno())
    raise SystemExit(0 if resume(args.archive_root, c, a, args.partial, inventory_sha256, len(inventory_assets))['verified'] else 1)
