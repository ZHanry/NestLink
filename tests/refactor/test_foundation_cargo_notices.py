"""Foundation source replacement must retain its exact original attribution."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('foundation_cargo_notices', ROOT / 'scripts/refactor-cargo-notices.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


class FoundationNoticeTests(unittest.TestCase):
    def fixture(self, root):
        review = N.REVIEWED_PLATFORM_FORKS['objc2-foundation']
        source = root / review['path']
        shutil.copytree(ROOT / review['path'], source)
        (root / 'docs/refactor').mkdir(parents=True)
        (root / 'docs/refactor/cargo-notice-supplements.json').write_text(json.dumps({'schema_version': 1, 'packages': []}))
        (root / 'LICENSE').write_bytes(b'fixture first-party license')
        (root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="objc2-foundation"\nversion="0.2.2"\n')
        item = {'id': 'foundation-reviewed-local', 'name': 'objc2-foundation', 'version': '0.2.2', 'source': None, 'manifest_path': str(source / 'Cargo.toml'), 'license': 'MIT', 'license_file': None, 'authors': [], 'repository': 'https://github.com/madsmtm/objc2'}
        return source, {'workspace_members': [], 'packages': [item]}

    def test_exact_archive_original_empty_authors_and_grant_survive_collection(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source, metadata = self.fixture(root)
            output = root / 'out'
            index = N.collect(root, metadata, output)
            self.assertEqual(index['status'], 'complete')
            record, = index['packages']
            self.assertEqual(record['authors_declared'], [])
            self.assertNotIn('first_party_license_path', record)
            self.assertEqual(record['local_source_path'], 'crates/platform-vendor/objc2-foundation')
            self.assertEqual(record['upstream_archive_sha256'], N.digest(source / 'UPSTREAM.crate'))
            self.assertEqual(record['local_review_manifest_sha256'], N.digest(source / 'UPSTREAM.json'))
            name = output / 'objc2-foundation-0.2.2'
            self.assertEqual((name / 'LICENSE').read_bytes(), (source / 'LICENSE').read_bytes())
            self.assertIn(b'Copyright (c) Steven Sheldon', (name / 'LICENSE').read_bytes())
            grant = next(item for item in record['files'] if item['path'].endswith('/LICENSE'))
            self.assertEqual(grant['upstream_url'], 'https://raw.githubusercontent.com/madsmtm/objc2/e282618be4c3a3b9542957e0c8540e9588472ce8/LICENSE.txt')
            self.assertTrue(grant['reviewed_full_license_text'])
            for filename in ('Cargo.toml.orig', '.cargo_vcs_info.json'):
                self.assertEqual((name / 'attribution' / filename).read_bytes(), (source / filename).read_bytes())
            original = tomllib.loads((name / 'attribution/Cargo.toml').read_text())
            local = tomllib.loads((name / 'local/Cargo.toml').read_text())
            self.assertEqual(original['package'].get('authors', []), [])
            self.assertEqual(original['package'], local['package'])
            self.assertIn('dispatch', original['dependencies'])
            self.assertNotIn('dispatch', local['dependencies'])
            self.assertIn('dispatch2', local['dependencies'])

    def test_source_archive_attribution_provenance_and_grant_edits_are_rejected(self):
        for filename in ('UPSTREAM.json', 'UPSTREAM.md', 'UPSTREAM.crate', 'LICENSE', 'Cargo.toml', 'Cargo.toml.orig', '.cargo_vcs_info.json', 'src/thread.rs', 'src/lib.rs'):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                source, metadata = self.fixture(root)
                target = source / filename
                target.write_bytes(target.read_bytes() + b'changed')
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')

    def test_unreviewed_path_workspace_reclassification_and_inferred_authors_are_rejected(self):
        for fault in ('path', 'workspace-member', 'version', 'license', 'authors', 'repository', 'extra-source'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                source, metadata = self.fixture(root)
                item = metadata['packages'][0]
                if fault == 'path':
                    destination = root / 'crates/platform-vendor/unreviewed'
                    shutil.copytree(source, destination)
                    item['manifest_path'] = str(destination / 'Cargo.toml')
                elif fault == 'workspace-member':
                    metadata['workspace_members'].append(item['id'])
                elif fault == 'extra-source':
                    (source / 'src/unreviewed.rs').write_bytes(b'// unreviewed source')
                elif fault == 'version':
                    item['version'] = '0.2.3'
                    lock = root / 'Cargo.lock'
                    lock.write_text(lock.read_text().replace('0.2.2', '0.2.3'))
                else:
                    item[fault] = ['Inferred holder'] if fault == 'authors' else 'unreviewed'
                with self.assertRaises(ValueError):
                    N.collect(root, metadata, root / 'out')

    def test_added_linked_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source, metadata = self.fixture(root)
            try:
                (source / 'src/linked.rs').symlink_to('../Cargo.toml')
            except OSError as error:
                self.skipTest('host cannot create a test source link: ' + str(error))
            with self.assertRaisesRegex(ValueError, 'linked source'):
                N.collect(root, metadata, root / 'out')


if __name__ == '__main__':
    unittest.main()
