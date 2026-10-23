"""Git dependency migration retains the exact reviewed source and notices."""
import importlib.util
import json
from pathlib import Path
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('dependency_git_notices', ROOT / 'scripts/refactor-cargo-notices.py')
N = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(N)


class GitForkNotices(unittest.TestCase):
    def fixture(self, root, fault=None):
        policy = json.loads((ROOT / 'config/dependency-forks.json').read_text(encoding='utf-8'))
        source = 'git+' + policy['repository'] + '?branch=' + policy['branch'] + '#' + policy['commit']
        if fault == 'commit':
            source = source.rsplit('#', 1)[0] + '#' + '0' * 40
        if fault == 'snapshot':
            policy['packages']['turn@0.17.2']['snapshot_sha256'] = '0' * 64
        if fault == 'directory':
            policy['packages']['turn@0.11.0']['directory'] = 'wrong-turn'
        (root / 'config').mkdir()
        (root / 'config/dependency-forks.json').write_text(json.dumps(policy), encoding='utf-8')
        (root / 'docs/refactor').mkdir(parents=True)
        (root / 'docs/refactor/cargo-notice-supplements.json').write_text('{"schema_version":1,"packages":[]}', encoding='utf-8')
        packages = []
        lock = 'version=4\n'
        for key, review in policy['packages'].items():
            name = review['name']
            path = N.dependency_fork_source(ROOT, name, review['version'])
            package = tomllib.loads((path / 'Cargo.toml').read_text(encoding='utf-8'))['package']
            packages.append({'id': key + '-git-id', 'name': name, 'version': review['version'], 'source': source, 'manifest_path': str(path / 'Cargo.toml'), 'license': package.get('license'), 'license_file': package.get('license-file'), 'authors': package.get('authors', []), 'repository': package.get('repository')})
            lock += '\n[[package]]\nname=' + json.dumps(name) + '\nversion=' + json.dumps(review['version']) + '\nsource=' + json.dumps(source) + '\n'
        (root / 'Cargo.lock').write_text(lock, encoding='utf-8')
        return {'workspace_members': [], 'packages': packages}

    def test_both_turn_versions_keep_original_notice_and_attribution(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            index = N.collect(root, self.fixture(root), root / 'notices')
            self.assertEqual(index['status'], 'complete')
            self.assertEqual(len(index['packages']), 6)
            self.assertEqual({p['version'] for p in index['packages'] if p['name'] == 'turn'}, {'0.11.0', '0.17.2'})
            for package in index['packages']:
                self.assertTrue(package['files'])
                self.assertTrue(package['attribution_files'])
                self.assertNotIn('first_party_license_path', package)

    def test_changed_commit_and_source_snapshot_are_rejected(self):
        for fault in ['commit', 'snapshot', 'directory']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                with self.assertRaises(ValueError):
                    N.collect(root, self.fixture(root, fault), root / 'notices')

    def test_ambiguous_turn_name_and_wrong_version_are_rejected(self):
        policy = json.loads((ROOT / 'config/dependency-forks.json').read_text(encoding='utf-8'))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            N.dependency_fork_review(policy, 'turn')
        with self.assertRaisesRegex(ValueError, 'Unknown'):
            N.dependency_fork_review(policy, 'turn', '9.9.9')
        self.assertEqual(N.dependency_fork_review(policy, 'turn', '0.11.0')['directory'], 'turn-client')

    def test_two_versions_cannot_share_a_source_directory(self):
        policy = json.loads((ROOT / 'config/dependency-forks.json').read_text(encoding='utf-8'))
        policy['packages']['turn@0.11.0']['directory'] = 'turn'
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            N.dependency_fork_review(policy, 'turn', '0.11.0')
