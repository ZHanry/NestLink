"""The Android package must not accept an ELF with a wrong ABI or small LOAD pages."""

import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("android_binary", ROOT / "scripts/verify-android-binary.py")
ANDROID = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANDROID)


def shared_elf(machine=183, alignment=16384, incongruent=False):
    data = bytearray(64 + 56 * 2)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 3, machine)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<HH", data, 52, 64, 56)
    struct.pack_into("<H", data, 56, 2)
    for index, (offset, virtual) in enumerate(((0, 0), (16384, 16384))):
        if incongruent and index == 1:
            virtual += 4096
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56, 1, 5, offset, virtual, virtual, 4096, 4096, alignment)
    return bytes(data)


class AndroidBinaryTests(unittest.TestCase):
    def check(self, payload, abi):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "libnestlink_android.so"
            library.write_bytes(payload)
            return ANDROID.verify(library, abi)

    def test_16k_arm64_and_x86_64_shared_objects_pass(self):
        self.assertEqual(len(self.check(shared_elf(), "arm64-v8a")["load_segments"]), 2)
        self.assertEqual(self.check(shared_elf(machine=62), "x86_64")["machine"], 62)

    def test_wrong_architecture_small_pages_and_incongruent_segments_fail(self):
        with self.assertRaises(ValueError):
            self.check(shared_elf(machine=62), "arm64-v8a")
        with self.assertRaises(ValueError):
            self.check(shared_elf(alignment=4096), "arm64-v8a")
        with self.assertRaises(ValueError):
            self.check(shared_elf(incongruent=True), "arm64-v8a")


if __name__ == "__main__":
    unittest.main()
