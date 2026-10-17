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
            policy['packages']['turn']['snapshot_sha256'] = '0' * 64
        (root / 'config').mkdir()
        (root / 'config/dependency-forks.json').write_text(json.dumps(policy), encoding='utf-8')
        (root / 'docs/refactor').mkdir(parents=True)
        (root / 'docs/refactor/cargo-notice-supplements.json').write_text('{"schema_version":1,"packages":[]}', encoding='utf-8')
        packages = []
        lock = 'version=4\n'
        for name, review in policy['packages'].items():
            path = N.dependency_fork_source(ROOT, name)
            package = tomllib.loads((path / 'Cargo.toml').read_text(encoding='utf-8'))['package']
            packages.append({'id': name + '-git-id', 'name': name, 'version': review['version'], 'source': source, 'manifest_path': str(path / 'Cargo.toml'), 'license': package.get('license'), 'license_file': package.get('license-file'), 'authors': package.get('authors', []), 'repository': package.get('repository')})
            lock += '\n[[package]]\nname=' + json.dumps(name) + '\nversion=' + json.dumps(review['version']) + '\nsource=' + json.dumps(source) + '\n'
        (root / 'Cargo.lock').write_text(lock, encoding='utf-8')
        return {'workspace_members': [], 'packages': packages}

    def test_all_five_forks_keep_original_notice_and_attribution(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            index = N.collect(root, self.fixture(root), root / 'notices')
            self.assertEqual(index['status'], 'complete')
            self.assertEqual(len(index['packages']), 5)
            for package in index['packages']:
                self.assertTrue(package['files'])
                self.assertTrue(package['attribution_files'])
                self.assertNotIn('first_party_license_path', package)

    def test_changed_commit_and_source_snapshot_are_rejected(self):
        for fault in ['commit', 'snapshot']:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                with self.assertRaises(ValueError):
                    N.collect(root, self.fixture(root, fault), root / 'notices')
