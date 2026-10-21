"""Cross-layer prehash digest lengths; callbacks perform no cryptography."""
import ctypes as ct
import unittest

from tools import native
from tools import test_native_boundaries as boundaries


class DigestBoundaries(unittest.TestCase):
    def setUp(self):
        self.fixture = boundaries.AdapterBoundaries()
        self.fixture.setUp()
        self.adapter, self.records = self.fixture.adapter, self.fixture.records
        self.attach, self.record = self.fixture.attach, self.fixture.record
        self.attach("slh_verify_digest", [native.VOID, native.U8P, ct.c_size_t,
            ct.c_int, native.U8P, ct.c_size_t, native.U8P, ct.c_size_t,
            native.U8P], self.verify_digest)

    def tearDown(self):
        self.fixture.tearDown()

    def verify_digest(self, ctx, sig, slen, alg, data, dlen, context, clen, pk):
        return self.record("verify_digest", alg, ct.string_at(data, dlen),
                           ct.string_at(context, clen))

    def test_all_digest_algorithms_accept_their_specified_lengths(self):
        # Independent expectations from the ABI's FIPS 205 prehash table.
        for name, size in (("sha256", 32), ("sha512", 64), ("shake128", 32),
                           ("shake256", 64), ("sm3", 32)):
            for identifier in (name, native.PREHASH[name]):
                digest = memoryview(bytes(range(size))).cast("I")
                with self.subTest(algorithm=identifier, operation="sign"):
                    signature = self.adapter.sign_digest(digest, bytes(64),
                                                         hash_alg=identifier, context=b"ctx")
                    self.assertEqual(len(signature), self.adapter.sig_bytes)
                    self.assertEqual(self.records[-1][1:],
                                     (native.PREHASH[name], bytes(range(size)), b"ctx"))
                with self.subTest(algorithm=identifier, operation="verify"):
                    self.assertTrue(self.adapter.verify_digest(digest, bytes(2320),
                        bytes(32), hash_alg=identifier, context=b"ctx"))
                    self.assertEqual(self.records[-1], ("verify_digest", native.PREHASH[name],
                                                        bytes(range(size)), b"ctx"))

    def test_wrong_digest_lengths_rejected_before_any_abi_call(self):
        for name, size in (("sha256", 32), ("sha512", 64), ("shake128", 32),
                           ("shake256", 64), ("sm3", 32)):
            for wrong_size in (0, size - 1, size + 1, 32 if size == 64 else 64):
                for operation in ("sign", "verify"):
                    with self.subTest(algorithm=name, length=wrong_size, operation=operation):
                        before = len(self.records)
                        with self.assertRaisesRegex(ValueError, "digest length"):
                            if operation == "sign":
                                self.adapter.sign_digest(bytes(wrong_size), bytes(64), hash_alg=name)
                            else:
                                self.adapter.verify_digest(bytes(wrong_size), bytes(2320), bytes(32), hash_alg=name)
                        self.assertEqual(len(self.records), before)

    def test_invalid_digest_algorithm_rejected_before_abi_call(self):
        for identifier in (0, 6, -1, 2**32, True, 1.5):
            with self.subTest(algorithm=identifier):
                with self.assertRaises((ValueError, TypeError)):
                    self.adapter.sign_digest(bytes(32), bytes(64), hash_alg=identifier)
        self.assertEqual(self.records, [])


if __name__ == "__main__":
    import unittest
    unittest.main()
