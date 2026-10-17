import hashlib, importlib.util, io, pathlib, tempfile, unittest
from unittest.mock import patch
from unittest.mock import Mock
spec = importlib.util.spec_from_file_location('ranges', pathlib.Path(__file__).resolve().parents[2] / 'scripts/refactor-release-resume.py')
ranges = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ranges)

class RangeTests(unittest.TestCase):

    def asset(self, data=b'original prefix and resumed bytes'):
        return {'asset_id': 123, 'bytes': len(data), 'github_sha256': hashlib.sha256(data).hexdigest(), 'state': 'uploaded'}

    def headers(self, status=206, content_range='bytes 3-8/9', length='6', extra=''):
        return io.BytesIO(f'HTTP/2.0 {status} response\r\nContent-Range: {content_range}\r\nContent-Length: {length}\r\n{extra}\r\n'.encode())

    def test_range_headers_reject_full_fallback_wrong_offset_total_and_encoding(self):
        self.assertEqual(ranges.range_headers(self.headers(), 3, 8, 9), {'start': 3, 'end': 8, 'total': 9, 'http_status': 206})
        for stream in [self.headers(status=200), self.headers(content_range='bytes 0-5/9'), self.headers(content_range='bytes 3-8/10'), self.headers(length='5'), self.headers(extra='Content-Encoding: gzip\r\n'), self.headers(extra='Content-Range: bytes 3-8/9\r\n'), io.BytesIO(b'HTTP/2.0 206 ok\r\nHeader: ' + b'x' * 5000 + b'\r\n\r\n')]:
            with self.assertRaises(ValueError):
                ranges.range_headers(stream, 3, 8, 9)

    def test_independent_resume_preserves_original_prefix_and_verifies_complete_blob(self):
        data = b'original prefix and resumed bytes'
        asset = self.asset(data)
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder).resolve()
            target = ranges.archive.asset_path(base, 'hub', asset)
            target.parent.mkdir(parents=True)
            original = target.with_name(target.name + '.' + '1' * 32 + '.part')
            original.write_bytes(data[:7])
            before = original.stat()
            seen = []

            def transfer(repo, a, start, end, path):
                seen.append((start, end))
                path.write_bytes(data[start:end + 1])
                return {'start': start, 'end': end, 'total': len(data), 'http_status': 206, 'sha256': ranges.archive.digest(path)}
            with patch.object(ranges.archive, 'metadata', return_value={}), patch.object(ranges, 'download_range', side_effect=transfer):
                report = ranges.resume(base, 'hub', asset, original)
            self.assertTrue(report['verified'])
            self.assertEqual(seen, [(7, len(data) - 1)])
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(original.read_bytes(), data[:7])
            self.assertEqual(original.stat().st_mtime_ns, before.st_mtime_ns)

    def test_bad_resumed_bytes_and_changed_metadata_never_promote_a_blob(self):
        for metadata_failure in (False, True):
            data = b'original prefix and resumed bytes'
            asset = self.asset(data)
            with tempfile.TemporaryDirectory() as folder:
                base = pathlib.Path(folder).resolve()
                target = ranges.archive.asset_path(base, 'hub', asset)
                target.parent.mkdir(parents=True)
                original = target.with_name(target.name + '.' + '2' * 32 + '.part')
                original.write_bytes(data[:7])

                def transfer(repo, a, start, end, path):
                    path.write_bytes(data[start:end + 1] if metadata_failure else b'x' * (end - start + 1))
                    return {'start': start, 'end': end, 'total': len(data), 'http_status': 206}
                with patch.object(ranges.archive, 'metadata', side_effect=[{}, ValueError('metadata changed')] if metadata_failure else None, return_value={}), patch.object(ranges, 'download_range', side_effect=transfer):
                    report = ranges.resume(base, 'hub', asset, original)
                self.assertFalse(report['verified'])
                self.assertFalse(target.exists())
                self.assertEqual(original.read_bytes(), data[:7])
                self.assertTrue((base / report['retained_partial']).exists())

    def test_arbitrary_prefix_paths_and_existing_corrupted_blobs_are_not_overwritten(self):
        asset = self.asset()
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder).resolve()
            source = base / 'arbitrary'
            source.write_bytes(b'keep source')
            with patch.object(ranges.archive, 'metadata', return_value={}), patch.object(ranges, 'download_range') as transfer:
                report = ranges.resume(base, 'hub', asset, source)
            self.assertFalse(report['verified'])
            transfer.assert_not_called()
            self.assertEqual(source.read_bytes(), b'keep source')
            target = ranges.archive.asset_path(base, 'hub', asset)
            target.write_bytes(b'keep corrupt existing blob')
            with patch.object(ranges.archive, 'metadata', return_value={}), patch.object(ranges, 'download_range') as transfer:
                report = ranges.resume(base, 'hub', asset)
            self.assertFalse(report['verified'])
            transfer.assert_not_called()
            self.assertEqual(target.read_bytes(), b'keep corrupt existing blob')

    def test_streamed_range_body_must_have_exact_bytes_before_success(self):
        for body, success in [(b'abcdef', True), (b'abc', False), (b'abcdefEXTRA', False)]:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as folder:
                target = pathlib.Path(folder) / 'chunk.range'
                header = self.headers().read()
                process = Mock(stdout=io.BytesIO(header + body))
                process.wait.return_value = 0
                process.poll.return_value = 0
                with patch.object(ranges.subprocess, 'Popen', return_value=process), patch.object(ranges.threading, 'Timer'):
                    if success:
                        result = ranges.download_range('ZHanry/home-tunnel', self.asset(b'123abcdef'), 3, 8, target)
                        self.assertEqual(target.read_bytes(), body)
                        self.assertEqual(result['sha256'], hashlib.sha256(body).hexdigest())
                    else:
                        with self.assertRaises(ValueError):
                            ranges.download_range('ZHanry/home-tunnel', self.asset(b'123abcdef'), 3, 8, target)

    def test_previously_assembled_partial_can_resume_without_mutating_it(self):
        data = b'original prefix and resumed bytes'
        asset = self.asset(data)
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder).resolve()
            target = ranges.archive.asset_path(base, 'hub', asset)
            target.parent.mkdir(parents=True)
            original = target.with_name(target.name + '.resume-' + '3' * 32 + '.part')
            original.write_bytes(data[:9])

            def transfer(repo, a, start, end, path):
                self.assertEqual(start, 9)
                path.write_bytes(data[start:end + 1])
                return {'start': start, 'end': end, 'total': len(data), 'http_status': 206}
            with patch.object(ranges.archive, 'metadata', return_value={}), patch.object(ranges, 'download_range', side_effect=transfer):
                report = ranges.resume(base, 'hub', asset, original)
            self.assertTrue(report['verified'])
            self.assertEqual(original.read_bytes(), data[:9])
            self.assertEqual(target.read_bytes(), data)

    def test_atomic_promotion_does_not_overwrite_a_destination_created_after_final_check(self):
        data = b'original prefix and resumed bytes'
        asset = self.asset(data)
        with tempfile.TemporaryDirectory() as folder:
            base = pathlib.Path(folder).resolve()
            target = ranges.archive.asset_path(base, 'hub', asset)
            target.parent.mkdir(parents=True)

            def transfer(repo, a, start, end, path):
                path.write_bytes(data[start:end + 1])
                return {'start': start, 'end': end, 'total': len(data), 'http_status': 206}

            def competing_writer(source, destination):
                target.write_bytes(b'concurrent copy must stay')
                raise FileExistsError('destination appeared')
            with patch.object(ranges.archive, 'metadata', return_value={}), patch.object(ranges, 'download_range', side_effect=transfer), patch.object(ranges.os, 'link', side_effect=competing_writer):
                report = ranges.resume(base, 'hub', asset)
            self.assertFalse(report['verified'])
            self.assertEqual(target.read_bytes(), b'concurrent copy must stay')
            self.assertEqual((base / report['retained_partial']).read_bytes(), data)
if __name__ == '__main__':
    unittest.main()
