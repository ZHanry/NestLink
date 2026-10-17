"""Release collection must bind full notice bytes to exact locked packages."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('cargo_notices_test', ROOT / 'scripts/refactor-cargo-notices.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)
SOURCE = 'registry+https://github.com/rust-lang/crates.io-index'


class NoticeTests(unittest.TestCase):
    def fixture(self, root, entries):
        (root / 'docs/refactor').mkdir(parents=True)
        (root / 'LICENSE').write_bytes(b'fixture product license')
        policy = root / 'docs/refactor/cargo-notice-supplements.json'
        policy.write_text(json.dumps({'schema_version': 1, 'packages': []}))
        archive = root / 'cargo/registry/cache/fixture-index/demo-1.2.3.crate'
        archive.parent.mkdir(parents=True)
        package = root / 'cargo/registry/src/fixture-index/demo-1.2.3'
        package.mkdir(parents=True)
        if not any(name == 'demo-1.2.3/Cargo.toml' for name, _, _ in entries):
            entries = [*entries, ('demo-1.2.3/Cargo.toml', b'[package]\nname="demo"\nversion="1.2.3"\nlicense="MIT"\n', tarfile.REGTYPE)]
        with tarfile.open(archive, 'w:gz') as stream:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(data) if kind == tarfile.REGTYPE else 0
                info.linkname = data.decode() if kind == tarfile.SYMTYPE else ''
                stream.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        (root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="demo"\nversion="1.2.3"\nsource="' + SOURCE + '"\nchecksum="' + checksum + '"\n')
        item = {'id': 'demo-id', 'name': 'demo', 'version': '1.2.3', 'source': SOURCE, 'manifest_path': str(package / 'Cargo.toml'), 'license': 'MIT', 'license_file': None}
        return {'workspace_members': [], 'packages': [item]}, policy, archive, checksum

    def test_preserves_complete_archive_notice_bytes_with_checksum_attribution(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            raw = b'\xef\xbb\xbfFull fixture license\r\nCopyright 2026 Holder\r\n'
            metadata, _, _, checksum = self.fixture(root, [('demo-1.2.3/LICENSE-MIT', raw, tarfile.REGTYPE), ('demo-1.2.3/NOTICE', b'fixture attribution\n', tarfile.REGTYPE)])
            output = root / 'out'
            index = N.collect(root, metadata, output)
            self.assertEqual((output / 'demo-1.2.3/LICENSE-MIT').read_bytes(), raw)
            self.assertEqual(index['packages'][0]['archive_sha256'], checksum)
            self.assertEqual(index['packages'][0]['files'][0]['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(json.loads((output / 'index.json').read_bytes()), index)

    def test_spdx_declaration_does_not_substitute_for_missing_license_text(self):
        for filename in ('README.md', 'src/license.rs'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata, _, _, _ = self.fixture(root, [('demo-1.2.3/' + filename, b'MIT', tarfile.REGTYPE)])
                with self.assertRaisesRegex(ValueError, 'Missing full Cargo license'):
                    N.collect(root, metadata, root / 'out')

    def test_license_filename_cannot_turn_a_label_or_url_into_full_terms(self):
        for raw in (b'MIT', b'SPDX-License-Identifier: MIT\n', b'https://opensource.org/license/MIT\n'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata, _, _, _ = self.fixture(root, [('demo-1.2.3/LICENSE', raw, tarfile.REGTYPE)])
                with self.assertRaises(N.MissingNotices) as raised:
                    N.collect(root, metadata, root / 'out')
                self.assertEqual(raised.exception.index['status'], 'incomplete')
                self.assertEqual((root / 'out/demo-1.2.3/LICENSE').read_bytes(), raw)

    def test_original_declaration_and_vcs_bytes_are_preserved_and_metadata_checked(self):
        for changed in (None, 'license', 'authors', 'repository'):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                original = b'[package]\nname="demo"\nversion="1.2.3"\nlicense="MIT"\n'
                vcs = b'{"git":{"sha1":"' + b'a' * 40 + b'"}}\n'
                metadata, _, _, _ = self.fixture(root, [('demo-1.2.3/LICENSE', b'Full fixture license', tarfile.REGTYPE), ('demo-1.2.3/Cargo.toml.orig', original, tarfile.REGTYPE), ('demo-1.2.3/.cargo_vcs_info.json', vcs, tarfile.REGTYPE)])
                if changed:
                    metadata['packages'][0][changed] = ['Different author'] if changed == 'authors' else 'different'
                    with self.assertRaisesRegex(ValueError, 'locked archive manifest'):
                        N.collect(root, metadata, root / 'out')
                else:
                    result = N.collect(root, metadata, root / 'out')
                    self.assertEqual((root / 'out/demo-1.2.3/attribution/Cargo.toml.orig').read_bytes(), original)
                    self.assertEqual((root / 'out/demo-1.2.3/attribution/.cargo_vcs_info.json').read_bytes(), vcs)
                    self.assertEqual(len(result['packages'][0]['attribution_files']), 3)

    def test_supplement_is_exact_version_archive_and_content_bound(self):
        for fault in (None, 'checksum', 'content', 'revision'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata, policy, _, checksum = self.fixture(root, [])
                path = root / 'packaging/notices/demo-LICENSE-MIT.txt'
                path.parent.mkdir(parents=True)
                path.write_bytes(b'Full fixture upstream license\n')
                entry = {'name': 'demo', 'version': '1.2.3', 'archive_sha256': checksum, 'license_declared': 'MIT', 'files': [{'path': path.relative_to(root).as_posix(), 'sha256': N.digest(path), 'full_license_text': True, 'upstream_url': 'https://raw.githubusercontent.com/example/demo/' + 'a' * 40 + '/LICENSE-MIT'}]}
                if fault == 'checksum':
                    entry['archive_sha256'] = '0' * 64
                if fault == 'content':
                    path.write_bytes(b'changed')
                if fault == 'revision':
                    entry['files'][0]['upstream_url'] = 'https://raw.githubusercontent.com/example/demo/main/LICENSE-MIT'
                policy.write_text(json.dumps({'schema_version': 1, 'packages': [entry]}))
                if fault is not None:
                    with self.assertRaises(ValueError):
                        N.collect(root, metadata, root / 'out')
                else:
                    index = N.collect(root, metadata, root / 'out')
                    self.assertEqual((root / 'out/demo-1.2.3/supplement/demo-LICENSE-MIT.txt').read_bytes(), path.read_bytes())
                    self.assertEqual(index['packages'][0]['files'][0]['upstream_url'], entry['files'][0]['upstream_url'])

    def test_sqlite_official_release_source_is_exactly_scoped(self):
        item = {'name': 'libsqlite3-sys', 'version': '0.35.0'}
        checksum = N.SQLITE_CRATE_ARCHIVE_SHA256
        entry = {
            'path': N.SQLITE_NOTICE_PATH,
            'sha256': N.SQLITE_NOTICE_SHA256,
            'upstream_url': N.SQLITE_UPSTREAM_RELEASE_URL,
            'upstream_archive_sha256': N.SQLITE_UPSTREAM_RELEASE_SHA256,
            'full_license_text': False,
        }
        self.assertTrue(N.reviewed_supplement_source(item, checksum, entry))
        for changed_item, changed_checksum, changed_entry in (
            ({**item, 'version': '0.35.1'}, checksum, entry),
            (item, '0' * 64, entry),
            (item, checksum, {**entry, 'upstream_url': 'https://www.sqlite.org/latest.zip'}),
            (item, checksum, {**entry, 'upstream_archive_sha256': '0' * 64}),
            (item, checksum, {**entry, 'path': 'packaging/notices/cargo-upstream/other.txt'}),
            (item, checksum, {**entry, 'full_license_text': True}),
        ):
            self.assertFalse(N.reviewed_supplement_source(changed_item, changed_checksum, changed_entry))

    def test_tampered_archive_and_omitted_lock_package_are_rejected(self):
        for fault in ('archive', 'metadata'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata, _, archive, _ = self.fixture(root, [('demo-1.2.3/LICENSE', b'fixture', tarfile.REGTYPE)])
                if fault == 'archive':
                    archive.write_bytes(archive.read_bytes() + b'tampered')
                else:
                    metadata['packages'] = []
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')

    def test_reviewed_authors_license_is_bound_to_original_archive_bytes(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                raw = b'Fixture AUTHORS containing complete license and original notices\n'
                metadata, policy, _, checksum = self.fixture(root, [('demo-1.2.3/AUTHORS', raw, tarfile.REGTYPE)])
                entry = {'name': 'demo', 'version': '1.2.3', 'archive_sha256': checksum, 'license_declared': 'MIT', 'archive_license_files': [{'path': 'AUTHORS', 'sha256': '0' * 64 if changed else hashlib.sha256(raw).hexdigest()}]}
                policy.write_text(json.dumps({'schema_version': 1, 'packages': [entry]}))
                if changed:
                    with self.assertRaisesRegex(ValueError, 'license bytes differ'):
                        N.collect(root, metadata, root / 'out')
                else:
                    index = N.collect(root, metadata, root / 'out')
                    self.assertEqual(index['status'], 'complete')
                    self.assertEqual((root / 'out/demo-1.2.3/AUTHORS').read_bytes(), raw)

    def test_missing_texts_retain_incomplete_inventory_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            metadata, _, _, _ = self.fixture(root, [])
            with self.assertRaises(N.MissingNotices) as raised:
                N.collect(root, metadata, root / 'out')
            self.assertEqual(raised.exception.index['status'], 'incomplete')
            self.assertEqual(raised.exception.index['unresolved_packages'][0]['name'], 'demo')
            self.assertEqual(json.loads((root / 'out/index.json').read_bytes()), raised.exception.index)

    def test_linked_escaping_duplicate_and_wrong_package_notices_are_rejected(self):
        cases = [[('demo-1.2.3/LICENSE', b'/outside', tarfile.SYMTYPE)], [('demo-1.2.3/../LICENSE', b'escape', tarfile.REGTYPE)], [('other-1.2.3/LICENSE', b'wrong', tarfile.REGTYPE)], [('demo-1.2.3/LICENSE', b'a', tarfile.REGTYPE), ('demo-1.2.3/LICENSE', b'b', tarfile.REGTYPE)]]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata, _, _, _ = self.fixture(root, entries)
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')
                self.assertFalse((root / 'LICENSE-outside').exists())


class LocalWebForkTests(unittest.TestCase):
    def fixture(self, root, metadata=None):
        (root / 'docs/refactor').mkdir(parents=True, exist_ok=True)
        (root / 'docs/refactor/cargo-notice-supplements.json').write_text(json.dumps({'schema_version': 1, 'packages': []}))
        (root / 'LICENSE').write_bytes(b'fixture first-party license')
        lock_path = root / 'Cargo.lock'
        lock = lock_path.read_text() if lock_path.exists() else 'version=4\n'
        metadata = metadata or {'workspace_members': [], 'packages': []}
        for name, review in N.REVIEWED_WEB_FORKS.items():
            path = root / review['path']
            shutil.copytree(ROOT / review['path'], path)
            lock += '\n[[package]]\nname="' + name + '"\nversion="' + review['version'] + '"\n'
            metadata['packages'].append({'id': name + '-local-id', 'name': name, 'version': review['version'], 'source': None, 'manifest_path': str(path / 'Cargo.toml'), 'license': 'MIT', 'license_file': None, 'authors': ['Greg Johnston'], 'repository': 'https://github.com/leptos-rs/leptos'})
        lock_path.write_text(lock)
        return metadata

    def test_reviewed_real_forks_preserve_original_attribution_and_mit_grant(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            metadata = self.fixture(root)
            output = root / 'out'
            index = N.collect(root, metadata, output)
            self.assertEqual(index['status'], 'complete')
            for record in index['packages']:
                name = record['name'] + '-' + record['version']
                source = root / record['local_source_path']
                self.assertNotIn('first_party_license_path', record)
                self.assertEqual(record['license_declared'], 'MIT')
                self.assertEqual(record['authors_declared'], ['Greg Johnston'])
                self.assertEqual((output / name / 'LICENSE').read_bytes(), (source / 'LICENSE').read_bytes())
                self.assertEqual((output / name / 'attribution/Cargo.toml.orig').read_bytes(), (source / 'Cargo.toml.orig').read_bytes())
                self.assertEqual((output / name / 'local/Cargo.toml').read_bytes(), (source / 'Cargo.toml').read_bytes())
                self.assertNotEqual((output / name / 'attribution/Cargo.toml').read_bytes(), (source / 'Cargo.toml').read_bytes())
                self.assertEqual(record['upstream_archive_sha256'], N.digest(source / 'UPSTREAM.crate'))
                self.assertEqual(record['local_review_manifest_sha256'], N.digest(source / 'UPSTREAM.json'))
            macro = next(record for record in index['packages'] if record['name'] == 'leptos_macro')
            self.assertIn('embedded commit is unavailable', macro['license_review_basis'])
            self.assertIn('not an exact embedded-commit claim', macro['license_review_basis'])

    def test_tampered_review_archive_original_source_edit_or_license_are_rejected(self):
        for filename in ('UPSTREAM.json', 'UPSTREAM.md', 'UPSTREAM.crate', 'LICENSE', 'Cargo.toml.orig', 'src/erased.rs'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata = self.fixture(root)
                target = root / 'crates/web-vendor/tachys' / filename
                target.write_bytes(target.read_bytes() + b'changed')
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')

    def test_unreviewed_path_source_file_and_first_party_reclassification_are_rejected(self):
        for fault in ('path', 'source-file', 'workspace-member', 'name', 'version', 'license', 'authors', 'repository'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                metadata = self.fixture(root)
                item = next(item for item in metadata['packages'] if item['name'] == 'tachys')
                if fault == 'path':
                    destination = root / 'crates/web-vendor/unreviewed'
                    shutil.copytree(root / 'crates/web-vendor/tachys', destination)
                    item['manifest_path'] = str(destination / 'Cargo.toml')
                elif fault == 'source-file':
                    (root / 'crates/web-vendor/tachys/src/unreviewed.rs').write_bytes(b'// new source')
                elif fault == 'workspace-member':
                    metadata['workspace_members'].append(item['id'])
                else:
                    item[fault] = ['Different author'] if fault == 'authors' else 'unreviewed'
                    if fault in ('name', 'version'):
                        lock = root / 'Cargo.lock'
                        lock.write_text(lock.read_text().replace('"tachys"' if fault == 'name' else '"0.2.19"', '"unreviewed"'))
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')

    def test_reviewed_web_forks_do_not_clear_an_unrelated_missing_original_notice(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            metadata, _, _, _ = NoticeTests().fixture(root, [])
            metadata = self.fixture(root, metadata)
            with self.assertRaises(N.MissingNotices) as raised:
                N.collect(root, metadata, root / 'out')
            self.assertEqual(raised.exception.index['status'], 'incomplete')
            self.assertEqual([item['name'] for item in raised.exception.index['unresolved_packages']], ['demo'])
            self.assertEqual(len(raised.exception.index['packages']), 3)


if __name__ == '__main__':
    unittest.main()
