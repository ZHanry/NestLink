"""Collect Cargo notices from exact locked archives and reviewed pinned supplements.

This collects source texts and attribution. It makes no legal conclusion about
license compatibility, which remains in the dependency/source review records.
No license text is synthesized from a manifest's SPDX declaration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tomllib


# These complete source snapshots were individually reviewed. A new path, source
# edit or provenance change requires a new review; this is not a vendor prefix.
REVIEWED_WEB_FORKS = {
    'leptos_macro': {
        'version': '0.8.19',
        'path': 'crates/web-vendor/leptos_macro',
        'provenance_sha256': 'fc52a1f51a034eebeb9608a417705d371df6b9ac288015d60c1d61112964e84d',
        'archive_sha256': '0902af1e6947ffc7e906b7003a165f76f178dc711a47b74241025090b0c32a72',
        'notes_sha256': '983e9aad0998ff5527a441cca9ae80f21b82f8c07caaa98d0f7840dc20ba4a8e',
    },
    'tachys': {
        'version': '0.2.19',
        'path': 'crates/web-vendor/tachys',
        'provenance_sha256': '274563f8ca26125ded5cbb85960ae34d7f5d11263158ee14d05dfbf3ad60d9f0',
        'archive_sha256': 'e47e2220bb9d2a3be976a22a0fb7685a0b84499bb11ea5cb3bbc82907675ac68',
        'notes_sha256': 'c0978dc5b4ee8ed63311bac4fa4f5fcedbde19a8a740b254638fc1408e31ab8a',
    },
}


REVIEWED_PLATFORM_FORKS = {
    'objc2-foundation': {
        'version': '0.2.2',
        'path': 'crates/platform-vendor/objc2-foundation',
        'provenance_sha256': '2373ea0c1353de94d3b7cfaab7dac3276662506616888ecb340fe4c38da356ea',
        'archive_sha256': '0ee638a5da3799329310ad4cfa62fbf045d5f56e3ef5ba4149e7452dcf89d5a8',
        'notes_sha256': '087325852f43d97016bc365fc7eca7d56ec1ed59789c418be4aec9179271754b',
    },
}
REVIEWED_LOCAL_FORKS = {**REVIEWED_WEB_FORKS, **REVIEWED_PLATFORM_FORKS}
REVIEWED_LICENSE_URLS = {
    'leptos_macro': 'https://raw.githubusercontent.com/leptos-rs/leptos/fbc9ed631ff8c19c5eed02a1d4459e202cff7043/LICENSE',
    'tachys': 'https://raw.githubusercontent.com/leptos-rs/leptos/584c3a2d884b0e4dba9e3f822a9b6982cff072c7/LICENSE',
    'objc2-foundation': 'https://raw.githubusercontent.com/madsmtm/objc2/e282618be4c3a3b9542957e0c8540e9588472ce8/LICENSE.txt',
}
SQLITE_UPSTREAM_RELEASE_URL = 'https://www.sqlite.org/2025/sqlite-amalgamation-3500200.zip'
SQLITE_UPSTREAM_RELEASE_SHA256 = '387991de2834b5da2894119ff4173a9ea0779ea55ebcf53d9a40b24d1dc2484e'
SQLITE_NOTICE_PATH = 'packaging/notices/cargo-upstream/sqlite-3.50.2-PUBLIC-DOMAIN.txt'
SQLITE_NOTICE_SHA256 = 'ad89cf5f9a0ca133418eae187ae954f2805fd3261aa00716642ed93fc7f3892d'
SQLITE_CRATE_ARCHIVE_SHA256 = '133c182a6a2c87864fe97778797e46c7e999672690dc9fa3ee8e241aa4a9c13f'


class MissingNotices(ValueError):
    def __init__(self, index):
        self.index = index
        super().__init__('Missing full Cargo license files: ' + ', '.join(p['name'] + '-' + p['version'] for p in index['unresolved_packages']))


def require(value, message):
    if not value:
        raise ValueError(message)


def reviewed_supplement_source(item, archive_sha256, value):
    url = value.get('upstream_url', '')
    if re.fullmatch(r'https://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[^\s]+', url):
        return True
    return (
        item.get('name') == 'libsqlite3-sys'
        and item.get('version') == '0.35.0'
        and archive_sha256 == SQLITE_CRATE_ARCHIVE_SHA256
        and value.get('path') == SQLITE_NOTICE_PATH
        and url == SQLITE_UPSTREAM_RELEASE_URL
        and value.get('upstream_archive_sha256') == SQLITE_UPSTREAM_RELEASE_SHA256
        and value.get('sha256') == SQLITE_NOTICE_SHA256
        and value.get('full_license_text') is False
    )


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def portable(value):
    require(isinstance(value, str) and value and len(value) <= 512 and '\\' not in value, 'Invalid Cargo notice path')
    parts = value.split('/')
    require(all(p not in ('', '.', '..') and not p.endswith((' ', '.')) for p in parts), 'Unsafe Cargo notice path')
    require(not any(ord(c) < 32 or c in ':<>"|?*' for c in value), 'Nonportable Cargo notice path')
    require(not any(re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?', p) for p in parts), 'Reserved Cargo notice path')
    return PurePosixPath(value)


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'Cargo notice input must be a regular file')
    return info


def notice_filename(name):
    return name.upper() in ('AUTHORS', 'AUTHORS.TXT', 'AUTHORS.MD') or re.search(r'(?i)(?:^|[-_.])(licen[sc]e|copying|notice|copyright|patents|unlicen[sc]e)(?:$|[-_.])', name) is not None


def license_filename(name):
    return notice_filename(name) and not name.lower().endswith(('.rs', '.py', '.sh', '.js', '.json')) and re.search(r'(?i)(licen[sc]e|copying|unlicen[sc]e)', name) is not None


def reference_only(raw, declared):
    text = raw.decode('utf-8-sig', errors='replace').strip()
    normalized = ' '.join(text.split())
    if declared and normalized == ' '.join(declared.split()):
        return True
    return text.startswith('SPDX-License-Identifier:') and '\n' not in text or re.fullmatch(r'https?://\S+', text) is not None


def write_file(root, relative, raw):
    destination = root.joinpath(*portable(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(raw)
    return {'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def policy_file(root, value):
    relative = portable(value)
    require(relative.parts[:2] == ('packaging', 'notices'), 'Cargo supplements must be committed packaging notices')
    path = root
    for part in relative.parts[:-1]:
        path /= part
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'Cargo supplement traverses a link')
    path /= relative.name
    require(0 < regular(path).st_size <= 4 * 1024 * 1024, 'Cargo supplement size is invalid')
    return path


def local_file(root, relative, budget=4 * 1024 * 1024):
    path = root
    parts = portable(relative).parts
    for part in parts[:-1]:
        path /= part
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'Local Cargo source traverses a link')
    path /= parts[-1]
    require(0 < regular(path).st_size <= budget, 'Local Cargo source file size is invalid')
    return path


def dependency_fork_review(policy, name, version=None):
    require(policy.get('schema_version') == 2, 'Unsupported dependency fork policy')
    matches = []
    identities = set()
    directories = set()
    for key, review in policy['packages'].items():
        identity = (review['name'], review['version'])
        directory = portable(review['directory'])
        require(len(directory.parts) == 1 and key == '@'.join(identity), 'Invalid dependency fork identity or directory')
        require(identity not in identities and review['directory'] not in directories, 'Ambiguous dependency fork policy')
        identities.add(identity)
        directories.add(review['directory'])
        if review['name'] == name and (version is None or review['version'] == version):
            matches.append(review)
    require(len(matches) == 1, 'Unknown or ambiguous dependency fork version')
    return matches[0]


def dependency_fork_source(root, name, version=None):
    policy = json.loads((root / 'config/dependency-forks.json').read_text(encoding='utf-8'))
    review = dependency_fork_review(policy, name, version)
    cargo = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')))
    matches = list((cargo / 'git/checkouts').glob('*/' + policy['commit'][:7] + '/' + review['directory']))
    require(len(matches) == 1, 'Run cargo fetch --locked before testing dependency fork sources')
    return matches[0]


def reviewed_local_fork(root, package_root, item, external=False):
    review = dict(REVIEWED_LOCAL_FORKS[item['name']])
    if external:
        review['path'] = package_root.name
    require(item['version'] == review['version'] and package_root == root / review['path'], 'Unreviewed local reviewed fork identity or path')
    provenance_path = local_file(root, review['path'] + '/UPSTREAM.json')
    require(digest(provenance_path) == review['provenance_sha256'], 'Local reviewed fork provenance differs from its review')
    provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
    require(provenance['schema_version'] == 1 and (provenance['package'], provenance['version']) == (item['name'], item['version']), 'Local reviewed fork provenance identity differs')
    require(provenance['published_archive'] == 'UPSTREAM.crate' and provenance['archive_sha256'] == review['archive_sha256'], 'Local reviewed fork archive binding differs')
    archive = local_file(root, review['path'] + '/UPSTREAM.crate', 256 * 1024 * 1024)
    require(digest(archive) == review['archive_sha256'], 'Local reviewed fork archive checksum differs')
    notes = local_file(root, review['path'] + '/UPSTREAM.md')
    require(digest(notes) == review['notes_sha256'], 'Local reviewed fork review notes differ')
    license_review = provenance['upstream_license_file']
    require(license_review['vendored_path'] == 'LICENSE' and license_review.get('full_license_text') is True, 'Local reviewed fork lacks a reviewed original license')
    require(license_review['upstream_url'] == REVIEWED_LICENSE_URLS[item['name']], 'Local reviewed fork license source differs from its exact review')
    license_path = local_file(root, review['path'] + '/LICENSE')
    require(digest(license_path) == license_review['sha256'] and not reference_only(license_path.read_bytes(), item.get('license')), 'Local reviewed fork original license differs')

    originals = {value['path']: value['sha256'] for value in provenance['original_archive_files']}
    changes = {value['path']: value for value in provenance['local_changes']}
    require(len(originals) == len(provenance['original_archive_files']) and len(changes) == len(provenance['local_changes']) and set(changes) <= set(originals), 'Local reviewed fork file review is inconsistent')
    expected_files = set(originals) | {'LICENSE', 'UPSTREAM.md', 'UPSTREAM.json', 'UPSTREAM.crate'}
    actual_files = set()
    for path in package_root.rglob('*'):
        info = path.lstat()
        require(not (getattr(info, 'st_file_attributes', 0) & 0x400) and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)), 'Local reviewed fork contains a linked source')
        if stat.S_ISREG(info.st_mode):
            actual_files.add(path.relative_to(package_root).as_posix())
    require(actual_files == expected_files, 'Local reviewed fork source inventory differs')
    original_attribution = {}
    archived = {}
    with tarfile.open(archive, 'r:gz') as stream:
        for count, member in enumerate(stream, 1):
            require(count <= 50000 and member.isfile() and 0 < member.size <= 4 * 1024 * 1024, 'Local reviewed fork archive member is invalid')
            path = portable(member.name)
            require(path.parts[0] == item['name'] + '-' + item['version'] and len(path.parts) > 1, 'Local reviewed fork archive path differs')
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            require(relative not in archived, 'Duplicate local reviewed fork archive member')
            raw = stream.extractfile(member).read()
            archived[relative] = hashlib.sha256(raw).hexdigest()
            if relative in ('Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json'):
                original_attribution[relative] = raw
    require(archived == originals, 'Local reviewed fork original archive inventory differs')
    for relative, original_sha256 in originals.items():
        change = changes.get(relative)
        if change is not None:
            require(change['original_sha256'] == original_sha256, 'Local reviewed fork edit has the wrong baseline')
        expected = change['local_sha256'] if change is not None else original_sha256
        require(digest(local_file(root, review['path'] + '/' + relative)) == expected, 'Local reviewed fork source bytes differ from their review')
    original_package = tomllib.loads(original_attribution['Cargo.toml'].decode('utf-8'))['package']
    local_package = tomllib.loads(local_file(root, review['path'] + '/Cargo.toml').read_text(encoding='utf-8'))['package']
    for package in (original_package, local_package):
        require((package.get('name'), package.get('version'), package.get('license'), package.get('license-file')) == (item['name'], item['version'], item.get('license'), item.get('license_file')), 'Local reviewed fork declarations differ from the original manifest')
        require(package.get('authors', []) == item.get('authors', []) and package.get('repository') == item.get('repository'), 'Local reviewed fork attribution differs from the original manifest')
    return provenance, original_attribution


def collect(root, metadata, destination):
    """Return an index and write one package directory per locked dependency."""
    root = root.resolve()
    require(not destination.exists(), 'Preserve an existing Cargo notice collection')
    destination.mkdir(parents=True)
    lock = tomllib.loads((root / 'Cargo.lock').read_text(encoding='utf-8'))['package']
    locked = {(p['name'], p['version'], p.get('source')): p for p in lock}
    policy_path = root / 'docs/refactor/cargo-notice-supplements.json'
    policy = json.loads(policy_path.read_text(encoding='utf-8'))
    require(policy.get('schema_version') == 1 and isinstance(policy.get('packages'), list), 'Unsupported Cargo notice supplements')
    supplements = {}
    for item in policy['packages']:
        key = (item['name'], item['version'], item['archive_sha256'])
        require(key not in supplements, 'Duplicate Cargo notice supplement')
        supplements[key] = item
    records = []
    unresolved = []
    seen = set()
    workspace = set(metadata['workspace_members'])
    for item in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'], p.get('source') or '')):
        key = (item['name'], item['version'], item.get('source'))
        require(key not in seen and key in locked, 'Cargo notice package differs from Cargo.lock')
        seen.add(key)
        name = item['name'] + '-' + item['version']
        portable(name)
        source = item.get('source')
        record = {'name': item['name'], 'version': item['version'], 'source': source, 'license_declared': item.get('license'), 'license_file_declared': item.get('license_file'), 'authors_declared': item.get('authors', []), 'repository_declared': item.get('repository'), 'files': [], 'attribution_files': []}
        if source and source.startswith('git+'):
            policy = json.loads((root / 'config/dependency-forks.json').read_text(encoding='utf-8'))
            expected_source = 'git+' + policy['repository'] + '?branch=' + policy['branch'] + '#' + policy['commit']
            require(source == expected_source, 'Unreviewed Cargo Git source')
            require(item['id'] not in workspace, 'A dependency fork cannot be first-party')
            review = dependency_fork_review(policy, item['name'], item['version'])
            package_root = Path(item['manifest_path']).parent.resolve()
            require(package_root.name == review['directory'], 'Dependency fork directory differs')
            snapshot = hashlib.sha256()
            files = sorted((path for path in package_root.rglob('*') if path.is_file()), key=lambda path: path.relative_to(package_root).as_posix())
            require(len(files) == review['file_count'], 'Dependency fork source inventory differs')
            for path in files:
                relative = path.relative_to(package_root).as_posix()
                local_file(package_root, relative, 256 * 1024 * 1024)
                snapshot.update((relative + '\0' + digest(path) + '\n').encode())
            require(snapshot.hexdigest() == review['snapshot_sha256'], 'Dependency fork source bytes differ')
            if item['name'] in REVIEWED_LOCAL_FORKS:
                provenance, attribution = reviewed_local_fork(package_root.parent, package_root, item, external=True)
                record['upstream_archive_sha256'] = provenance['archive_sha256']
                record['license_review_basis'] = provenance['license_review_basis']
                for filename, raw in sorted(attribution.items()):
                    record['attribution_files'].append(write_file(destination, name + '/attribution/' + filename, raw))
            for path in files:
                if notice_filename(path.name) or path.name in ('UPSTREAM.md', 'UPSTREAM.json'):
                    record['files'].append(write_file(destination, name + '/' + path.relative_to(package_root).as_posix(), path.read_bytes()))
            require(any(license_filename(PurePosixPath(p['path']).name) for p in record['files']), 'Dependency fork lacks full upstream license files')
            record['git_commit'] = policy['commit']
            record['reviewed_source_sha256'] = review['snapshot_sha256']
            record['attribution_files'].append(write_file(destination, name + '/patched/Cargo.toml', (package_root / 'Cargo.toml').read_bytes()))
            records.append(record)
            continue
        if source is None:
            package_root = Path(item['manifest_path']).parent.resolve()
            require(package_root.is_relative_to(root), 'Local Cargo source is outside the release checkout')
            if item['name'] in REVIEWED_LOCAL_FORKS:
                require(item['id'] not in workspace, 'Reviewed third-party fork must be excluded from workspace members')
                provenance, attribution = reviewed_local_fork(root, package_root, item)
                for filename in ('LICENSE', 'UPSTREAM.md', 'UPSTREAM.json'):
                    entry = write_file(destination, name + '/' + filename, (package_root / filename).read_bytes())
                    if filename == 'LICENSE':
                        entry['reviewed_full_license_text'] = True
                        entry['upstream_url'] = provenance['upstream_license_file']['upstream_url']
                    record['files'].append(entry)
                for filename, raw in sorted(attribution.items()):
                    record['attribution_files'].append(write_file(destination, name + '/attribution/' + filename, raw))
                record['attribution_files'].append(write_file(destination, name + '/local/Cargo.toml', (package_root / 'Cargo.toml').read_bytes()))
                record['local_source_path'] = package_root.relative_to(root).as_posix()
                record['upstream_archive_sha256'] = provenance['archive_sha256']
                record['local_review_manifest_sha256'] = REVIEWED_LOCAL_FORKS[item['name']]['provenance_sha256']
                record['license_review_basis'] = provenance['license_review_basis']
                records.append(record)
                continue
            if item['id'] in workspace:
                record['first_party_license_path'] = 'LICENSE'
                record['first_party_license_sha256'] = digest(root / 'LICENSE')
                records.append(record)
                continue
            # The two reviewed local WebRTC forks retain their upstream texts.
            require(package_root.is_relative_to(root / 'crates/traversal/vendor'), 'Unreviewed local third-party source')
            for path in sorted(package_root.rglob('*')):
                if path.is_file() and (notice_filename(path.name) or path.name == 'UPSTREAM.md'):
                    require(regular(path).st_size <= 4 * 1024 * 1024, 'Local notice exceeds its budget')
                    record['files'].append(write_file(destination, name + '/' + path.relative_to(package_root).as_posix(), path.read_bytes()))
            require(any(license_filename(PurePosixPath(p['path']).name) for p in record['files']), 'Local third-party source lacks full license files')
            record['local_source_path'] = package_root.relative_to(root).as_posix()
            records.append(record)
            continue
        require(source == 'registry+https://github.com/rust-lang/crates.io-index', 'Unreviewed Cargo registry or Git source')
        package_root = Path(item['manifest_path']).parent
        require(package_root.name == name and package_root.parent.parent.name == 'src' and package_root.parent.parent.parent.name == 'registry', 'Unexpected Cargo registry layout')
        archive = package_root.parent.parent.parent / 'cache' / package_root.parent.name / (name + '.crate')
        require(regular(archive).st_size <= 256 * 1024 * 1024, 'Cargo archive exceeds its budget')
        checksum = digest(archive)
        require(re.fullmatch(r'[0-9a-f]{64}', locked[key].get('checksum', '')) and checksum == locked[key]['checksum'], 'Cargo archive checksum differs from Cargo.lock')
        record['archive_sha256'] = checksum
        supplement = supplements.get((item['name'], item['version'], checksum))
        reviewed_archive_files = {}
        if supplement is not None:
            require(supplement['license_declared'] == item.get('license'), 'Cargo supplement declaration differs')
            reviewed_archive_files = {p['path']: p['sha256'] for p in supplement.get('archive_license_files', [])}
            record['supplement_review_basis'] = supplement.get('review_basis')
        archived_names = set()
        notice_bytes = 0
        manifest_checked = False
        with tarfile.open(archive, 'r:gz') as stream:
            for count, member in enumerate(stream, 1):
                require(count <= 50000, 'Cargo archive member budget exceeded')
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and '..' not in path.parts and path.parts[0] == name, 'Unsafe Cargo archive member')
                relative = path.relative_to(name).as_posix()
                require(relative not in archived_names, 'Duplicate Cargo archive member')
                archived_names.add(relative)
                declared = item.get('license_file') == relative
                legal_directory = any(part.lower() in ('licenses', 'licences') for part in path.parts[1:-1])
                attribution = relative in ('Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json')
                if attribution:
                    require(member.isfile() and 0 < member.size <= 4 * 1024 * 1024, 'Cargo attribution is empty, linked or oversized')
                    raw = stream.extractfile(member).read()
                    if relative == 'Cargo.toml':
                        package = tomllib.loads(raw.decode('utf-8'))['package']
                        require((package.get('name'), package.get('version'), package.get('license'), package.get('license-file')) == (item['name'], item['version'], item.get('license'), item.get('license_file')), 'Cargo metadata declarations differ from the locked archive manifest')
                        require(package.get('authors', []) == item.get('authors', []) and package.get('repository') == item.get('repository'), 'Cargo metadata attribution differs from the locked archive manifest')
                        manifest_checked = True
                    record['attribution_files'].append(write_file(destination, name + '/attribution/' + relative, raw))
                if not (declared or notice_filename(path.name) or relative in reviewed_archive_files or legal_directory and member.isfile()):
                    continue
                require(member.isfile() and 0 < member.size <= 4 * 1024 * 1024, 'Cargo notice is empty, linked or oversized')
                notice_bytes += member.size
                require(notice_bytes <= 64 * 1024 * 1024, 'Cargo package notice budget exceeded')
                raw = stream.extractfile(member).read()
                entry = write_file(destination, name + '/' + relative, raw)
                entry['declared_license_file'] = declared
                if relative in reviewed_archive_files:
                    require(reviewed_archive_files[relative] == entry['sha256'], 'Reviewed Cargo archive license bytes differ')
                entry['reviewed_full_license_text'] = reviewed_archive_files.get(relative) == entry['sha256']
                entry['full_license_filename_candidate'] = (declared or license_filename(path.name)) and not reference_only(raw, item.get('license'))
                require(not entry['reviewed_full_license_text'] or not reference_only(raw, item.get('license')), 'Reviewed Cargo license contains only a reference')
                record['files'].append(entry)
        require(manifest_checked, 'Locked Cargo archive lacks its published manifest')
        require(set(reviewed_archive_files) <= archived_names, 'Reviewed Cargo archive license file is absent')
        if supplement is not None:
            for value in supplement.get('files', []):
                path = policy_file(root, value['path'])
                require(digest(path) == value['sha256'], 'Cargo supplement bytes differ from their review')
                require(reviewed_supplement_source(item, checksum, value), 'Cargo supplement source is not an exact upstream revision or reviewed SQLite source release')
                entry = write_file(destination, name + '/supplement/' + PurePosixPath(value['path']).name, path.read_bytes())
                entry['upstream_url'] = value['upstream_url']
                if value.get('upstream_archive_sha256') is not None:
                    require(value['upstream_archive_sha256'] == SQLITE_UPSTREAM_RELEASE_SHA256, 'Cargo supplement source archive differs from the reviewed SQLite release')
                    entry['upstream_archive_sha256'] = value['upstream_archive_sha256']
                entry['review_path'] = 'docs/refactor/cargo-notice-supplements.json'
                entry['reviewed_full_license_text'] = value.get('full_license_text') is True
                require(not entry['reviewed_full_license_text'] or not reference_only(path.read_bytes(), item.get('license')), 'Reviewed Cargo supplement contains only a reference')
                record['files'].append(entry)
        if not any(p.get('reviewed_full_license_text') or p.get('full_license_filename_candidate') for p in record['files']):
            unresolved.append({'name': item['name'], 'version': item['version'], 'archive_sha256': checksum, 'license_declared': item.get('license')})
        records.append(record)
    require(seen == set(locked), 'Cargo metadata does not cover every locked dependency')
    index = {'schema_version': 1, 'scope': 'Exact locked Cargo notice collection and reviewed source supplements; license compatibility conclusions remain in separate review records', 'status': 'incomplete' if unresolved else 'complete', 'cargo_lock_sha256': digest(root / 'Cargo.lock'), 'supplements_sha256': digest(policy_path), 'packages': records, 'unresolved_packages': unresolved}
    write_file(destination, 'index.json', (json.dumps(index, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    if unresolved:
        raise MissingNotices(index)
    return index
