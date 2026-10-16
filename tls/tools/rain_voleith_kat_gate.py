"""Known-answer gate for the Rain-VOLEitH native library (production and test builds).

    python tools/rain_voleith_kat_gate.py --release build/rain_voleith_tls.dll \
        --test build/native-rain-test/rain_voleith_tls_test.dll --kat-dir ../KAT --rain-src ../src

Checks, each of which must pass:

  A  ABI version, processor check, the six parameter-set names and sizes (frozen signature lengths)
  B  the production library verifies the six published signature KATs; corrupting the signature, the
     message or either half of the public key is rejected; wrong lengths and other sets' indices give
     the length error
  C  the test library, seeded with the seed recorded in each KAT file, reproduces sk, pk and sm byte
     for byte (seed -> keygen -> sign, the KAT generator's splitmix64 stream)
  D  the test library derives public keys from the secret keys of the key-generation KATs in
     src/rain_kat.hpp (KAT3, KAT4: 11 rows each, against the three sets of the same Rain), including
     the rejected keys
  E  random round trips for every set (message lengths 0/1/130/1000): two signatures of one message
     differ, both verify, corruption is rejected, a wrong key is rejected, wrong lengths are refused
  F  a failing random source: keygen and sign return the random-source error with wiped outputs, and
     signing works again afterwards
  G  invalid set indices, and six threads generating, signing and verifying concurrently

Prints a JSON summary and exits non-zero when any check fails.
"""
import argparse
import ctypes
import hashlib
import json
import random
import re
import sys
import threading
from pathlib import Path

OK, ERR_SET, ERR_LENGTH, ERR_RANDOM, ERR_INVALID = 0, -1, -2, -3, -4
NAMES = ["rain3-fast", "rain3-bal", "rain3-short", "rain4-fast", "rain4-bal", "rain4-short"]
SIG_BYTES = {"rain3-fast": 4146, "rain3-bal": 3706, "rain3-short": 3014,
             "rain4-fast": 4112, "rain4-bal": 4080, "rain4-short": 3190}


class Lib:
    def __init__(self, path, test):
        self.path = path
        self.d = d = ctypes.CDLL(str(path))
        d.rain_tls_abi_version.restype = ctypes.c_int
        d.rain_tls_cpu_supported.restype = ctypes.c_int
        d.rain_tls_set_count.restype = ctypes.c_int
        d.rain_tls_set_name.restype = ctypes.c_char_p
        d.rain_tls_set_name.argtypes = [ctypes.c_int]
        sz = ctypes.POINTER(ctypes.c_size_t)
        d.rain_tls_set_sizes.argtypes = [ctypes.c_int, sz, sz, sz]
        d.rain_tls_keygen.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        d.rain_tls_sign.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                    ctypes.c_char_p, ctypes.c_size_t]
        d.rain_tls_verify.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                      ctypes.c_char_p, ctypes.c_size_t]
        if test:
            d.rain_tls_test_deterministic.argtypes = [ctypes.c_uint64]
            d.rain_tls_test_deterministic.restype = None
            d.rain_tls_test_system_random.restype = None
            d.rain_tls_test_fail_random.argtypes = [ctypes.c_int]
            d.rain_tls_test_fail_random.restype = None
            d.rain_tls_test_public_key.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]

    def sizes(self, i):
        a, b, c = ctypes.c_size_t(), ctypes.c_size_t(), ctypes.c_size_t()
        rc = self.d.rain_tls_set_sizes(i, ctypes.byref(a), ctypes.byref(b), ctypes.byref(c))
        return rc, a.value, b.value, c.value

    def keygen(self, i, pkn, skn):
        pk, sk = ctypes.create_string_buffer(pkn), ctypes.create_string_buffer(skn)
        rc = self.d.rain_tls_keygen(i, pk, pkn, sk, skn)
        return rc, pk.raw, sk.raw

    def sign(self, i, sign_len, msg, sk):
        sig = ctypes.create_string_buffer(sign_len)
        rc = self.d.rain_tls_sign(i, sig, sign_len, msg, len(msg), sk, len(sk))
        return rc, sig.raw

    def verify(self, i, sig, msg, pk):
        return self.d.rain_tls_verify(i, sig, len(sig), msg, len(msg), pk, len(pk))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def flip(b, pos):
    a = bytearray(b)
    a[pos] ^= 0x01
    return bytes(a)


def parse_sigkat(path):
    text = path.read_text(encoding="utf-8")
    seed = int(re.search(r"det_seed=0x([0-9a-f]+)", text).group(1), 16)
    fields = dict(re.findall(r"^(sk|pk|msg|sm) = ([0-9a-f]+)$", text, re.M))
    return seed, {k: bytes.fromhex(v) for k, v in fields.items()}


def parse_keygen_kat(path):
    text = path.read_text(encoding="utf-8")
    out = {}
    for name in ("KAT3", "KAT4"):
        body = text.split("inline constexpr kat %s[" % name, 1)[1].split("};", 1)[0]
        rows = re.findall(r'\{"([^"]*)",\s*\{([^}]*)\},\s*\{([^}]*)\},\s*(\d),', body)
        out[name] = [(tag, bytes(int(x, 16) for x in sk.split(",")), bytes(int(x, 16) for x in pk.split(",")), int(rej))
                     for tag, sk, pk, rej in rows]
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--release", required=True, help="production library (rain_voleith_tls.dll)")
    ap.add_argument("--test", required=True, help="test library (rain_voleith_tls_test.dll)")
    ap.add_argument("--kat-dir", required=True, help="directory with sigkat_*.txt and SHA256SUMS")
    ap.add_argument("--rain-src", required=True, help="the Rain-VOLEitH source tree (for rain_kat.hpp)")
    args = ap.parse_args()
    kat_dir, rain_src = Path(args.kat_dir), Path(args.rain_src)
    prod = Lib(Path(args.release), test=False)
    test = Lib(Path(args.test), test=True)
    checks = []

    def check(group, item, ok, detail=""):
        checks.append({"group": group, "item": item, "ok": bool(ok), "detail": str(detail)})
        if not ok:
            print("FAIL", group, item, detail)

    # A
    sizes = {}
    for lib, tag in ((prod, "release"), (test, "test")):
        check("A", tag + " abi", lib.d.rain_tls_abi_version() == 1)
        check("A", tag + " cpu", lib.d.rain_tls_cpu_supported() == 1)
        check("A", tag + " set_count", lib.d.rain_tls_set_count() == len(NAMES))
        for i, n in enumerate(NAMES):
            check("A", "%s name %d" % (tag, i), lib.d.rain_tls_set_name(i) == n.encode())
            rc, pkn, skn, sgn = lib.sizes(i)
            check("A", "%s sizes %s" % (tag, n), rc == OK and pkn == 32 and skn == 32 and sgn == SIG_BYTES[n],
                  (pkn, skn, sgn))
            sizes[n] = (pkn, skn, sgn)
        check("A", tag + " name out of range", lib.d.rain_tls_set_name(len(NAMES)) is None)

    # B + C
    sums = {}
    for line in (kat_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split()
            sums[name.lstrip("*")] = digest
    for i, n in enumerate(NAMES):
        path = kat_dir / ("sigkat_%s.txt" % n.replace("-", "_"))
        check("B", "sigkat file hash " + n, sums.get(path.name) == sha256(path))
        seed, kat = parse_sigkat(path)
        msg, sm, pk, sk = kat["msg"], kat["sm"], kat["pk"], kat["sk"]
        sig = sm[len(msg):]
        check("B", "sm = msg || sig " + n, sm[:len(msg)] == msg and len(sig) == SIG_BYTES[n])
        check("B", "verify KAT " + n, prod.verify(i, sig, msg, pk) == OK)
        for pos in (0, len(sig) // 2, len(sig) - 1):
            check("B", "tampered sig byte %d %s" % (pos, n), prod.verify(i, flip(sig, pos), msg, pk) == ERR_INVALID)
        check("B", "tampered msg " + n, prod.verify(i, sig, flip(msg, 7), pk) == ERR_INVALID)
        check("B", "tampered pk (pt half) " + n, prod.verify(i, sig, msg, flip(pk, 3)) == ERR_INVALID)
        check("B", "tampered pk (ct half) " + n, prod.verify(i, sig, msg, flip(pk, 20)) == ERR_INVALID)
        check("B", "short sig " + n, prod.verify(i, sig[:-1], msg, pk) == ERR_LENGTH)
        check("B", "long sig " + n, prod.verify(i, sig + b"\0", msg, pk) == ERR_LENGTH)
        check("B", "short pk " + n, prod.verify(i, sig, msg, pk[:-1]) == ERR_LENGTH)
        for j, other in enumerate(NAMES):
            if other != n:
                check("B", "cross-set %s->%s" % (n, other), prod.verify(j, sig, msg, pk) == ERR_LENGTH)
        test.d.rain_tls_test_deterministic(seed)
        rc, pk2, sk2 = test.keygen(i, 32, 32)
        rc2, sig2 = test.sign(i, SIG_BYTES[n], msg, sk2)
        test.d.rain_tls_test_system_random()
        check("C", "reproduce %s (seed 0x%016x)" % (n, seed),
              rc == OK and rc2 == OK and pk2 == pk and sk2 == sk and msg + sig2 == sm)

    # D
    kg = parse_keygen_kat(rain_src / "rain_kat.hpp")
    check("D", "keygen KAT rows", len(kg["KAT3"]) == 11 and len(kg["KAT4"]) == 11)
    for kat_name, prefix in (("KAT3", "rain3-"), ("KAT4", "rain4-")):
        for n in [x for x in NAMES if x.startswith(prefix)]:
            i = NAMES.index(n)
            for tag, sk, pk, rej in kg[kat_name]:
                out = ctypes.create_string_buffer(32)
                rc = test.d.rain_tls_test_public_key(i, out, sk)
                ok = (rc == 0) if rej else (rc == 1 and out.raw == pk)
                check("D", "%s %s %s" % (n, kat_name, tag), ok, "rc=%d reject=%d" % (rc, rej))

    # E
    rng = random.Random(20261016)
    for i, n in enumerate(NAMES):
        pkn, skn, sgn = sizes[n]
        rc, pk, sk = prod.keygen(i, pkn, skn)
        check("E", "keygen " + n, rc == OK and any(pk) and any(sk))
        for mlen in (0, 1, 130, 1000):
            msg = bytes(rng.getrandbits(8) for _ in range(mlen))
            rc1, s1 = prod.sign(i, sgn, msg, sk)
            rc2, s2 = prod.sign(i, sgn, msg, sk)
            check("E", "sign/verify %s len %d" % (n, mlen),
                  rc1 == OK and rc2 == OK and prod.verify(i, s1, msg, pk) == OK and prod.verify(i, s2, msg, pk) == OK)
            check("E", "randomized %s len %d" % (n, mlen), s1 != s2)
            check("E", "tamper %s len %d" % (n, mlen), prod.verify(i, flip(s1, rng.randrange(sgn)), msg, pk) == ERR_INVALID)
            if mlen:
                check("E", "msg tamper %s len %d" % (n, mlen),
                      prod.verify(i, s1, flip(msg, rng.randrange(mlen)), pk) == ERR_INVALID)
        rc_other, pk_other, _ = prod.keygen(i, pkn, skn)
        rc1, s1 = prod.sign(i, sgn, b"wrong key", sk)
        check("E", "wrong key " + n, rc_other == OK and prod.verify(i, s1, b"wrong key", pk_other) == ERR_INVALID)
        check("E", "sign wrong sk length " + n,
              prod.d.rain_tls_sign(i, ctypes.create_string_buffer(sgn), sgn, b"m", 1, sk[:-1], skn - 1) == ERR_LENGTH)
        check("E", "keygen wrong length " + n, prod.keygen(i, pkn - 1, skn)[0] == ERR_LENGTH)

    # F
    for i in (0, 4):
        n = NAMES[i]
        pkn, skn, sgn = sizes[n]
        test.d.rain_tls_test_fail_random(1)
        rc, pk, sk = test.keygen(i, pkn, skn)
        check("F", "keygen RNG failure %s" % n, rc == ERR_RANDOM and not any(pk) and not any(sk))
        test.d.rain_tls_test_fail_random(0)
        rc, pk, sk = test.keygen(i, pkn, skn)
        test.d.rain_tls_test_fail_random(1)
        rc2, sig = test.sign(i, sgn, b"m", sk)
        check("F", "sign RNG failure %s" % n, rc == OK and rc2 == ERR_RANDOM and not any(sig))
        test.d.rain_tls_test_system_random()
        rc3, sig = test.sign(i, sgn, b"m", sk)
        check("F", "recovered %s" % n, rc3 == OK and test.verify(i, sig, b"m", pk) == OK)

    # G
    for bad in (-1, len(NAMES), 1000):
        check("G", "bad set %d sizes" % bad, prod.sizes(bad)[0] == ERR_SET)
        check("G", "bad set %d keygen" % bad, prod.keygen(bad, 32, 32)[0] == ERR_SET)
        check("G", "bad set %d verify" % bad, prod.verify(bad, b"x" * 10, b"m", b"p" * 32) == ERR_SET)
    errors = []

    def worker(seed):
        r = random.Random(seed)
        for _ in range(15):
            i = r.choice([0, 1, 3, 4])
            pkn, skn, sgn = sizes[NAMES[i]]
            rc, pk, sk = prod.keygen(i, pkn, skn)
            msg = bytes(r.getrandbits(8) for _ in range(130))
            rc2, s = prod.sign(i, sgn, msg, sk)
            if rc or rc2 or prod.verify(i, s, msg, pk) != OK or prod.verify(i, flip(s, 5), msg, pk) != ERR_INVALID:
                errors.append((seed, NAMES[i]))

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("G", "6 threads x 15 keygen/sign/verify", not errors, errors[:3])

    failed = [c for c in checks if not c["ok"]]
    groups = {}
    for c in checks:
        groups.setdefault(c["group"], [0, 0])
        groups[c["group"]][0 if c["ok"] else 1] += 1
    summary = {"total": len(checks), "passed": len(checks) - len(failed), "failed": len(failed),
               "groups": {g: {"passed": p, "failed": f} for g, (p, f) in sorted(groups.items())},
               "release_sha256": sha256(args.release), "test_sha256": sha256(args.test)}
    print(json.dumps(summary, indent=1))
    print("RESULT", "PASS" if not failed else "FAIL", "(%d failed of %d)" % (len(failed), len(checks)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
