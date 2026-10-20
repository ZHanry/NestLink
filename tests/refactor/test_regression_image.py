import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('regression_image', Path(__file__).parents[2] / 'scripts/refactor-regression-image.py')
image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image)
SOURCE = 'a' * 40


def fixture(source=SOURCE, architecture='arm64', reverse_docker=False, corrupt=False, unsafe=False, manifests=1):
    entries = {}

    def put(value):
        raw = json.dumps(value, separators=(',', ':')).encode() if isinstance(value, dict) else value
        digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
        entries['blobs/sha256/' + digest.split(':')[1]] = raw
        return {'digest': digest, 'size': len(raw)}

    layers = []
    for name in ('one', 'two'):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w') as stream:
            member = tarfile.TarInfo(name)
            member.size = 1
            stream.addfile(member, io.BytesIO(b'x'))
        layers.append(dict(put(layer.getvalue()), mediaType='application/vnd.oci.image.layer.v1.tar'))
    config = put({'architecture': architecture, 'os': 'linux',
                  'config': {'User': '65532:65532', 'Labels': {
                      'org.opencontainers.image.revision': source, 'lat.hap.nestlink.purpose': 'regression'}},
                  'rootfs': {'diff_ids': [layer['digest'] for layer in layers]}})
    manifest = put({'schemaVersion': 2, 'config': config, 'layers': layers})
    manifest['mediaType'] = 'application/vnd.oci.image.manifest.v1+json'
    entries['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [manifest] * manifests}).encode()
    paths = ['blobs/sha256/' + layer['digest'].split(':')[1] for layer in layers]
    entries['manifest.json'] = json.dumps([{'Config': 'blobs/sha256/' + config['digest'].split(':')[1],
                                          'Layers': list(reversed(paths)) if reverse_docker else paths}]).encode()
    if corrupt:
        entries['blobs/sha256/' + config['digest'].split(':')[1]] += b' '
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as stream:
        for name, raw in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            stream.addfile(member, io.BytesIO(raw))
        if unsafe:
            member = tarfile.TarInfo('../outside')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            stream.addfile(member)
    return result.getvalue(), config['digest'], manifest['digest']


class RegressionImageTests(unittest.TestCase):
    def inspect(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'image.tar.gz'
            path.write_bytes(raw)
            return image.inspect_archive(path, SOURCE)

    def test_classic_and_containerd_identities_bind_the_same_source_and_layers(self):
        raw, config, manifest = fixture()
        self.assertNotEqual(config, manifest)
        result = self.inspect(raw)
        self.assertEqual((result['config_sha256'], result['oci_manifest_sha256']), (config, manifest))
        self.assertEqual(len(result['rootfs_diff_ids']), 2)
        self.assertEqual(result['source_revision'], SOURCE)

    def test_wrong_source_and_platform_are_rejected(self):
        for options in ({'source': 'b' * 40}, {'architecture': 'amd64'}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.inspect(fixture(**options)[0])

    def test_altered_config_and_reordered_layer_graphs_are_rejected(self):
        for options in ({'corrupt': True}, {'reverse_docker': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.inspect(fixture(**options)[0])

    def test_linked_traversal_and_ambiguous_manifest_are_rejected(self):
        for options in ({'unsafe': True}, {'manifests': 0}, {'manifests': 2}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.inspect(fixture(**options)[0])


if __name__ == '__main__':
    unittest.main()
