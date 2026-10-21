"""Rain-VOLEitH signatures through the native library in ``native/rain_voleith``.

Rain-VOLEitH is a VOLE-in-the-head signature: the rFAEST proof system with the Rain one-way
function (three or four rounds over GF(2^128)) in place of AES. Its public key is 32 bytes and
signing and verifying take well under a millisecond in the fast and balanced sets, so a server
can sign every CertificateVerify afresh, as with Falcon or ML-DSA and unlike a stateful XMSS key.

The C library wraps the signature code without changing it: every call goes through the same
``crypto_sign_keypair`` / ``crypto_sign`` / ``crypto_sign_open`` functions that the published
known-answer tests exercise.

The library is found through ``RAIN_VOLEITH_LIB`` or, without it, at ``build/rain_voleith_tls.dll``
(``build/librain_voleith_tls.so`` elsewhere) in this checkout, and is loaded once per process.
There is no pure-Python fallback: when the library is missing, was built for another interface
version, or the processor lacks the instructions it was compiled for, constructing a signer raises
:class:`~tls.errors.BackendUnavailableError`, so a profile that asks for Rain-VOLEitH fails closed
instead of silently running something else.
"""

from __future__ import annotations

import ctypes
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import BackendUnavailableError, HybridTLSError

__all__ = [
    "RAIN_LIB_ENV",
    "RAIN_SCHEME_IDS",
    "RAIN_SETS",
    "RainSecretKey",
    "RainVoleith",
    "RainVoleithError",
    "rain_library_path",
]

#: Environment variable naming the native library; the default is under ``build/``.
RAIN_LIB_ENV = "RAIN_VOLEITH_LIB"

#: Interface version of ``rain_voleith_tls.h`` this module was written against.
_ABI_VERSION = 1
_OK = 0

#: The six Rain-VOLEitH parameter sets: Rain with 3 or 4 rounds, each in a fast, a balanced
#: and a short-signature configuration (4146/3706/3014 and 4112/4080/3190 bytes).
RAIN_SETS = ("rain3-fast", "rain3-bal", "rain3-short", "rain4-fast", "rain4-bal", "rain4-short")

#: Private-use code points. XMSS takes 0xFE00 + height for heights 1-32 (0xFE01-0xFE20), and the
#: hybrid payload carries its own scheme fields, so these only need to be distinct here.
RAIN_SCHEME_IDS = {
    "rain3-fast": 0xFEB0,
    "rain3-bal": 0xFEB1,
    "rain3-short": 0xFEB2,
    "rain4-fast": 0xFEB3,
    "rain4-bal": 0xFEB4,
    "rain4-short": 0xFEB5,
}

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_NAME = "rain_voleith_tls.dll" if os.name == "nt" else "librain_voleith_tls.so"


class RainVoleithError(HybridTLSError):
    """The native library reported a failure while generating a key or signing."""


def rain_library_path() -> Path:
    """Return the library path this process uses: ``RAIN_VOLEITH_LIB``, or the ``build/`` default."""
    override = os.environ.get(RAIN_LIB_ENV)
    return Path(override) if override else _PROJECT_ROOT / "build" / _DEFAULT_NAME


class _Library:
    """The loaded DLL/shared object and the parameter sets it reports."""

    def __init__(self, path: Path) -> None:
        if not path.is_file():
            raise BackendUnavailableError(
                f"signature library not found at {path}; build it with native/rain_voleith/build.py "
                f"or set {RAIN_LIB_ENV}"
            )
        try:
            lib = ctypes.CDLL(str(path))
        except OSError as error:
            raise BackendUnavailableError(f"cannot load the Rain-VOLEitH library {path}: {error}") from error
        lib.rain_tls_abi_version.restype = ctypes.c_int
        lib.rain_tls_cpu_supported.restype = ctypes.c_int
        # The processor check comes first: the signature code is compiled for x86-64-v3 plus
        # AES-NI and PCLMULQDQ, and calling into it on an older processor would fault.
        if lib.rain_tls_cpu_supported() != 1:
            raise BackendUnavailableError(
                "this processor lacks the instructions the Rain-VOLEitH library needs (x86-64-v3, AES-NI, PCLMULQDQ)"
            )
        if lib.rain_tls_abi_version() != _ABI_VERSION:
            raise BackendUnavailableError(
                f"Rain-VOLEitH library {path} has interface version {lib.rain_tls_abi_version()}, "
                f"expected {_ABI_VERSION}"
            )
        size = ctypes.POINTER(ctypes.c_size_t)
        buffer = ctypes.c_char_p
        lib.rain_tls_set_count.restype = ctypes.c_int
        lib.rain_tls_set_name.restype = ctypes.c_char_p
        lib.rain_tls_set_name.argtypes = [ctypes.c_int]
        lib.rain_tls_set_sizes.restype = ctypes.c_int
        lib.rain_tls_set_sizes.argtypes = [ctypes.c_int, size, size, size]
        lib.rain_tls_keygen.restype = ctypes.c_int
        lib.rain_tls_keygen.argtypes = [ctypes.c_int, buffer, ctypes.c_size_t, buffer, ctypes.c_size_t]
        lib.rain_tls_sign.restype = ctypes.c_int
        lib.rain_tls_sign.argtypes = [ctypes.c_int, buffer, ctypes.c_size_t, buffer, ctypes.c_size_t, buffer,
                                      ctypes.c_size_t]
        lib.rain_tls_verify.restype = ctypes.c_int
        lib.rain_tls_verify.argtypes = [ctypes.c_int, buffer, ctypes.c_size_t, buffer, ctypes.c_size_t, buffer,
                                        ctypes.c_size_t]
        self.path = path
        self.lib = lib
        #: name -> (index, public key bytes, secret key bytes, signature bytes)
        self.sets: dict[str, tuple[int, int, int, int]] = {}
        for index in range(lib.rain_tls_set_count()):
            raw_name = lib.rain_tls_set_name(index)
            if raw_name is None:
                continue
            pk, sk, sig = ctypes.c_size_t(), ctypes.c_size_t(), ctypes.c_size_t()
            if lib.rain_tls_set_sizes(index, ctypes.byref(pk), ctypes.byref(sk), ctypes.byref(sig)) == _OK:
                self.sets[raw_name.decode("ascii")] = (index, pk.value, sk.value, sig.value)


_load_lock = threading.Lock()
_loaded: dict[str, _Library | BackendUnavailableError] = {}


def _library() -> _Library:
    """Load the library at :func:`rain_library_path` once per path and process."""
    path = rain_library_path()
    key = str(path)
    with _load_lock:
        cached = _loaded.get(key)
        if cached is None:
            try:
                cached = _Library(path)
            except BackendUnavailableError as error:
                cached = error
            _loaded[key] = cached
    if isinstance(cached, BackendUnavailableError):
        raise BackendUnavailableError(str(cached))
    return cached


@dataclass(frozen=True)
class RainSecretKey:
    """A packed secret key (32 bytes) bound to the parameter set that generated it.

    Binding the set name to the key makes signing with another set's key an error instead of a
    signature nobody can verify. The key bytes are kept out of ``repr``.
    """

    scheme: str
    key: bytes = field(repr=False)


class RainVoleith:
    """One Rain-VOLEitH parameter set behind :class:`~tls.pq.backends.PqSigner`."""

    #: Typed secret-key constructor, used when an offline fixture reloads key bytes.
    secret_key_type = RainSecretKey

    def __init__(self, name: str) -> None:
        if name not in RAIN_SCHEME_IDS:
            raise BackendUnavailableError(f"unknown Rain-VOLEitH parameter set {name!r}")
        library = _library()
        entry = library.sets.get(name)
        if entry is None:
            raise BackendUnavailableError(f"the Rain-VOLEitH library {library.path} does not provide {name}")
        self._lib = library.lib
        self._index, self.public_key_bytes, self.secret_key_bytes, self.signature_bytes = entry
        self.name = name
        self.scheme_id = RAIN_SCHEME_IDS[name]
        self.post_quantum = True

    def keygen(self) -> tuple[RainSecretKey, bytes]:
        """Generate a key pair from the operating system's random source."""
        public_key = ctypes.create_string_buffer(self.public_key_bytes)
        secret_key = ctypes.create_string_buffer(self.secret_key_bytes)
        code = self._lib.rain_tls_keygen(self._index, public_key, self.public_key_bytes, secret_key,
                                         self.secret_key_bytes)
        if code != _OK:
            raise RainVoleithError(f"{self.name} key generation failed (library code {code})")
        return RainSecretKey(self.name, secret_key.raw), public_key.raw

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message``; every signature draws fresh randomness, so two signatures differ."""
        if not isinstance(secret_key, RainSecretKey) or secret_key.scheme != self.name:
            raise ValueError(f"{self.name} signs only with a secret key generated by {self.name}")
        message = bytes(message)
        signature = ctypes.create_string_buffer(self.signature_bytes)
        code = self._lib.rain_tls_sign(self._index, signature, self.signature_bytes, message, len(message),
                                       secret_key.key, len(secret_key.key))
        if code != _OK:
            raise RainVoleithError(f"{self.name} signing failed (library code {code})")
        return signature.raw

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Return whether ``signature`` is valid; lengths are checked before the library is called."""
        try:
            public_key, message, signature = bytes(public_key), bytes(message), bytes(signature)
        except (TypeError, ValueError):
            return False
        if len(public_key) != self.public_key_bytes or len(signature) != self.signature_bytes:
            return False
        code = self._lib.rain_tls_verify(self._index, signature, len(signature), message, len(message), public_key,
                                         len(public_key))
        return code == _OK
