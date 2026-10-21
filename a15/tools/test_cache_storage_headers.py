"""Reject malformed cache metadata before allocating or entering native code."""
import struct
import tempfile
import unittest
from pathlib import Path

from tools.measure_cache_storage import header, PARAM_SHAPES


class CacheHeaderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "public.cache"

    def write_header(self, *, pid=3, level=22, height=22, n=16, payload=16, body=16):
        data = bytearray(96 + body)
        data[:8] = b"A15CACHE"
        struct.pack_into(">6I", data, 8, 1, pid, level, height, n, payload)
        self.path.write_bytes(data)

    def test_supported_root_only_headers(self):
        for pid, shape in PARAM_SHAPES.items():
            with self.subTest(pid=pid):
                self.write_header(pid=pid, level=shape[0], height=shape[0])
                self.assertEqual(header(self.path)["file_bytes"], 112)

    def test_untrusted_shape_fields_rejected_before_shift(self):
        for change in ({"height": 0xffffffff}, {"pid": 0xffffffff},
                       {"level": 0xffffffff}, {"n": 0xffffffff}, {"height": 21}):
            with self.subTest(change=change):
                self.write_header(**change)
                with self.assertRaisesRegex(ValueError, "parameter fields"):
                    header(self.path)

    def test_declared_and_actual_sizes_must_match(self):
        self.write_header(payload=17)
        with self.assertRaisesRegex(ValueError, "node size"):
            header(self.path)
        self.write_header(body=17)
        with self.assertRaisesRegex(ValueError, "file size"):
            header(self.path)


if __name__ == "__main__":
    unittest.main()
