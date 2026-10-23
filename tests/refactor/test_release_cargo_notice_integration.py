"""The real metadata producer must package notices or retain a blocking index."""
from argparse import Namespace
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    specification = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(value)
    return value


P = module('release_notice_integration_producer', 'scripts/refactor-release-producer.py')
N = module('release_notice_integration_collector', 'scripts/refactor-cargo-notices.py')


class ReleaseNoticeIntegrationTests(unittest.TestCase):
    def exercise(self, missing):
        for declared, expected in ((None, 'NOASSERTION'), ('MIT', 'MIT'), ('MIT/Apache-2.0', 'MIT OR Apache-2.0'), ('MIT / Apache-2.0', 'MIT OR Apache-2.0'), ('Apache-2.0/MIT', 'Apache-2.0 OR MIT'), ('Unlicense/MIT', 'Unlicense OR MIT')):
            self.assertEqual(P.cargo_license_expression(declared), expected)
        with self.assertRaisesRegex(ValueError, 'Unreviewed legacy Cargo'):
            P.cargo_license_expression('unknown/other')
        with tempfile.TemporaryDirectory() as scratch:
            base = Path(scratch)
            root, output = base / 'source', base / 'output'
            root.mkdir()
            inputs = {'LICENSE': b'fixture product license', 'Cargo.toml': b'fixture',
                      'rust-toolchain.toml': b'fixture', 'docs/refactor/source-ledger.json': b'{}',
                      'docs/refactor/native-codecs.lock.json': b'{"sources":[]}',
                      'docs/refactor/cargo-notice-supplements.json': b'{"schema_version":1,"packages":[]}',
                      'scripts/refactor-cargo-notices.py': (ROOT / 'scripts/refactor-cargo-notices.py').read_bytes(),
                      'config/release-producer.json': b'{}',
                      'config/product-scope.json': b'{}',
                      'packaging/notices/fixture-NOTICE': b'fixture existing notice\n'}
            for relative, raw in inputs.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            archive = base / 'cargo/registry/cache/fixture-index/demo-1.2.3.crate'
            archive.parent.mkdir(parents=True)
            manifest = b'[package]\nname="demo"\nversion="1.2.3"\nlicense="Apache-2.0/MIT"\n'
            original_license = b'Full fixture upstream permission and attribution\r\n'
            entries = [('Cargo.toml', manifest)] + ([] if missing else [('LICENSE-MIT', original_license)])
            with tarfile.open(archive, 'w:gz') as stream:
                for name, raw in entries:
                    entry = tarfile.TarInfo('demo-1.2.3/' + name)
                    entry.size = len(raw)
                    stream.addfile(entry, io.BytesIO(raw))
            source = 'registry+https://github.com/rust-lang/crates.io-index'
            (root / 'Cargo.lock').write_text('version=4\n[[package]]\nname="demo"\nversion="1.2.3"\nsource="' + source + '"\nchecksum="' + hashlib.sha256(archive.read_bytes()).hexdigest() + '"\n', encoding='utf-8')
            package = base / 'cargo/registry/src/fixture-index/demo-1.2.3'
            package.mkdir(parents=True)
            metadata = {'workspace_members': [], 'packages': [{'id': 'fixture-demo', 'name': 'demo', 'version': '1.2.3', 'license': 'Apache-2.0/MIT', 'license_file': None, 'manifest_path': str(package / 'Cargo.toml'), 'source': source}]}
            cohort = {'version': '15.0.0', 'source_revision': '1' * 40, 'source_epoch': 1, 'run_id': 1, 'run_attempt': 1}
            cohort_path = base / 'cohort.json'
            cohort_path.write_text(json.dumps(cohort), encoding='utf-8')
            calls = []

            def run(command, **_kwargs):
                calls.append(command)
                if command[:2] == ['git', 'archive']:
                    target = Path(next(arg.removeprefix('--output=') for arg in command if arg.startswith('--output=')))
                    target.write_bytes(b'fixture source archive')
                if command[:2] == ['cargo', 'metadata']:
                    return json.dumps(metadata).encode()
                return b'fixture tool version'

            args = Namespace(cohort=cohort_path, output=output)
            with patch.object(P, 'ROOT', root), patch.object(P, 'load_cohort', return_value=(cohort, {})), patch.object(P, 'run', side_effect=run), patch.object(P, 'module', return_value=N):
                if missing:
                    with self.assertRaises(N.MissingNotices):
                        P.metadata(args)
                else:
                    P.metadata(args)
            self.assertTrue(any(command[:2] == ['cargo', 'metadata'] and '--all-features' in command and '--locked' in command for command in calls))
            index = json.loads((output / 'evidence/cargo-notice-index.json').read_bytes())
            sbom = json.loads((output / 'NestLink-build-sbom.spdx.json').read_bytes())
            self.assertEqual(sbom['packages'][0]['licenseDeclared'], 'Apache-2.0 OR MIT')
            self.assertIn('Apache-2.0/MIT', sbom['packages'][0]['sourceInfo'])
            self.assertEqual(index['packages'][0]['license_declared'], 'Apache-2.0/MIT')
            if missing:
                self.assertEqual(index['status'], 'incomplete')
                self.assertEqual(index['unresolved_packages'][0]['name'], 'demo')
                self.assertFalse((output / 'parts/metadata.json').exists())
                self.assertFalse((output / 'NestLink-build-licenses.tar.gz').exists())
            else:
                self.assertEqual(index['status'], 'complete')
                with tarfile.open(output / 'NestLink-build-licenses.tar.gz', 'r:gz') as stream:
                    self.assertEqual(stream.extractfile('cargo/demo-1.2.3/LICENSE-MIT').read(), original_license)
                    self.assertEqual(json.loads(stream.extractfile('cargo/index.json').read()), index)
                receipt = json.loads((output / 'parts/metadata.json').read_bytes())
                self.assertTrue(any(p['role'] == 'cargo-notice-index' for p in receipt['evidence']))

    def test_complete_original_notices_are_in_the_actual_metadata_archive(self):
        self.exercise(False)

    def test_missing_original_notices_retain_the_index_and_block_metadata_success(self):
        self.exercise(True)


if __name__ == '__main__':
    unittest.main()
