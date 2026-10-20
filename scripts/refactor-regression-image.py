"""Bind Docker config and OCI manifest identities in one regression archive."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')


def inspect_archive(path, source, architecture='arm64'):
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('full lowercase source SHA required')
    with tarfile.open(path, 'r:*') as stream:
        members = {}
        total = 0
        for member in stream:
            name = PurePosixPath(member.name)
            if (member.name in members or name.is_absolute() or '..' in name.parts
                    or not (member.isfile() or member.isdir()) or len(members) >= 20000):
                raise ValueError('unsafe or oversized archive structure')
            total += member.size
            if total > 1024 * 1024 * 1024:
                raise ValueError('archive exceeds 1 GiB unpacked budget')
            members[member.name] = member

        def read(name, maximum=4 * 1024 * 1024):
            member = members.get(name)
            if member is None or not member.isfile() or not 0 < member.size <= maximum:
                raise ValueError('missing, empty or oversized archive member')
            return stream.extractfile(member).read()

        def blob(digest, maximum=4 * 1024 * 1024):
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise ValueError('invalid OCI digest')
            raw = read('blobs/sha256/' + digest.split(':')[1], maximum)
            if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('OCI blob bytes differ from digest')
            return raw

        index = json.loads(read('index.json'))
        if index.get('schemaVersion') != 2 or len(index.get('manifests', [])) != 1:
            raise ValueError('exactly one OCI image manifest is required')
        descriptor = index['manifests'][0]
        if descriptor.get('mediaType') != 'application/vnd.oci.image.manifest.v1+json':
            raise ValueError('unsupported manifest type')
        raw = blob(descriptor['digest'])
        if descriptor.get('size') != len(raw):
            raise ValueError('manifest size differs')
        manifest = json.loads(raw)
        if manifest.get('schemaVersion') != 2:
            raise ValueError('unsupported OCI schema')
        config_digest = manifest['config']['digest']
        config_raw = blob(config_digest)
        if manifest['config'].get('size') != len(config_raw):
            raise ValueError('config size differs')
        config = json.loads(config_raw)
        labels = config.get('config', {}).get('Labels', {})
        if (config.get('architecture') != architecture or config.get('os') != 'linux'
                or config.get('config', {}).get('User') != '65532:65532'
                or labels.get('org.opencontainers.image.revision') != source
                or labels.get('lat.hap.nestlink.purpose') != 'regression'):
            raise ValueError('image platform, user, source or purpose differs')
        docker = json.loads(read('manifest.json'))
        if len(docker) != 1 or docker[0].get('Config') != 'blobs/sha256/' + config_digest.split(':')[1]:
            raise ValueError('Docker config does not bind the OCI image')
        diff_ids = config.get('rootfs', {}).get('diff_ids')
        layers = manifest.get('layers', [])
        if not isinstance(diff_ids, list) or not 1 <= len(layers) <= 128 or len(layers) != len(diff_ids):
            raise ValueError('invalid root filesystem layer budget')
        expected_paths = []
        for layer, diff_id in zip(layers, diff_ids):
            if layer.get('mediaType') != 'application/vnd.oci.image.layer.v1.tar' or layer.get('digest') != diff_id:
                raise ValueError('regression archive requires uncompressed, digest-bound layers')
            raw = blob(diff_id, 1024 * 1024 * 1024)
            if layer.get('size') != len(raw):
                raise ValueError('layer size differs')
            expected_paths.append('blobs/sha256/' + diff_id.split(':')[1])
        if docker[0].get('Layers') != expected_paths:
            raise ValueError('Docker and OCI layer ordering differs')
        return {'config_sha256': config_digest, 'oci_manifest_sha256': descriptor['digest'],
                'rootfs_diff_ids': diff_ids, 'architecture': architecture, 'os': 'linux',
                'source_revision': source}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect_archive(args.archive, args.source)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
