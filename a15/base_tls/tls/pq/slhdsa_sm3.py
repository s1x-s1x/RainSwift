"""Lazy SLH-DSA-SM3 backend; C signs, independent Python can verify.

The constructor allocates no key, tree, native context or process pool.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

from ..errors import BackendUnavailableError

PARAMETERS = {
    "slh-dsa-sm3-128s": (1, 0xFEA0, 7856),
    "slh-dsa-sm3-128f": (2, 0xFEA1, 17088),
    "slh-dsa-sm3-128-24": (3, 0xFEA2, 3856),
}
TLS_ROOT = Path(__file__).resolve().parents[2]
# A1-5 keeps tools/reference above base_tls; TLS-B keeps them beside tls/.
PROJECT_ROOT = TLS_ROOT.parent if TLS_ROOT.name == "base_tls" else TLS_ROOT


class SlhDsaSm3:
    post_quantum = True
    public_key_bytes = 32
    secret_key_bytes = 64

    def __init__(self, name="slh-dsa-sm3-128-24", *, library=None, threads=1,
                 force_python=False, require_native=False, backend=0):
        if name not in PARAMETERS:
            raise BackendUnavailableError(f"unknown SLH variant {name!r}")
        if type(threads) is not int or not 1 <= threads <= 1024:
            raise ValueError("SLH thread allocation must be explicit and positive")
        if type(backend) is not int or backend not in (0, 1, 2, 5):
            raise ValueError("SLH backend must be 0, 1, 2 or 5")
        if type(force_python) is not bool or type(require_native) is not bool:
            raise ValueError("SLH backend policy flags must be bools")
        self.name = name
        self.pid, self.scheme_id, self.signature_bytes = PARAMETERS[name]
        self.library = library
        self.threads, self.force_python, self.backend = threads, force_python, backend
        if force_python and require_native:
            raise ValueError("force_python and require_native are mutually exclusive")
        self.require_native = require_native
        self.last_verification = None
        self.max_signatures = 1 << 24 if self.pid == 3 else None
        self._signing_contexts = {}
        self._cache_ready = set()

    @staticmethod
    def _modules():
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.append(str(PROJECT_ROOT))

    @staticmethod
    def _local_module(relative, label):
        """Load this checkout's implementation, not another cached tools/reference."""
        path = (PROJECT_ROOT / relative).resolve()
        if not path.is_file():
            raise BackendUnavailableError(f"SLH {label} module missing from this checkout: {path}")
        suffix = hashlib.sha256(str(PROJECT_ROOT).encode()).hexdigest()[:16]
        name = f"_hybrid_slh_{label}_{suffix}"
        loaded = sys.modules.get(name)
        if loaded is not None:
            if Path(loaded.__file__).resolve() != path:
                raise BackendUnavailableError(f"SLH {label} module origin mismatch")
            return loaded
        options = {"submodule_search_locations": [str(path.parent)]} if path.name == "__init__.py" else {}
        spec = importlib.util.spec_from_file_location(name, path, **options)
        if spec is None or spec.loader is None:
            raise BackendUnavailableError(f"SLH {label} module has no loader: {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            for key in list(sys.modules):
                if key == name or key.startswith(name + "."):
                    sys.modules.pop(key, None)
            raise
        return module

    def _native(self):
        self._modules()
        path = self.library or os.environ.get("SLHDSA_SM3_LIB") or os.environ.get("A15_NATIVE_LIBRARY")
        path = path or PROJECT_ROOT / "build" / ("slhdsa_sm3.dll" if os.name == "nt" else "libslhdsa_sm3.so")
        try:
            adapter = self._local_module("tools/native.py", "native")
            return adapter.NativeSlhDsa(self.pid, threads=self.threads,
                                        flags=self.backend | 0x100, library=path)
        except BackendUnavailableError:
            raise
        except (ImportError, OSError, AttributeError, RuntimeError) as error:
            raise BackendUnavailableError(f"SLH native backend unavailable: {type(error).__name__}: {error}") from error

    def keygen(self):
        native = self._native()
        try:
            public, secret = native.keygen()
        except Exception:
            native.close()
            raise
        if bytes(public) != bytes(secret)[32:64]:
            native.close()
            raise BackendUnavailableError("SLH keygen returned inconsistent public and secret keys")
        self._signing_contexts[bytes(secret)] = native
        # The C keygen contract builds its upper-tree cache in this context.
        self._cache_ready.add(bytes(secret))
        return secret, public

    def sign(self, secret_key: object, message: bytes, *, require_cache: bool = False) -> bytes:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 64:
            raise ValueError("SLH secret key must contain 64 bytes")
        secret = bytes(secret_key)
        existing = self._signing_contexts.get(secret)
        cache_ready = secret in self._cache_ready
        if require_cache and not cache_ready:
            raise BackendUnavailableError(
                "SLH signing requires a built or loaded cache for this key; a bound "
                "native context alone is not a cache"
            )
        if existing is not None:
            self.last_signing = {"mode": "cached-context" if cache_ready else "uncached-bound-context",
                                 "cache_ready": cache_ready, "algorithm": self.name,
                                 "backend": existing.backend, "threads": self.threads}
            return existing.sign(bytes(message), secret, context=b"")
        with self._native() as native:
            self.last_signing = {"mode": "uncached-temporary-context", "cache_ready": False,
                                 "algorithm": self.name, "backend": native.backend,
                                 "threads": self.threads}
            return native.sign(bytes(message), secret, context=b"")

    def bind_signing_context(self, secret_key: object, *, cache_path=None,
                             public_key: bytes | None = None, level: int | None = None):
        """Reuse one native context for a key, optionally loading an explicit cache.

        A cache is never assumed to load implicitly: the caller names the path and
        the public key it must be bound to. A wrong key or damaged cache fails here,
        not at the first signature.
        """
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 64:
            raise ValueError("SLH secret key must contain 64 bytes")
        secret = bytes(secret_key)
        if public_key is not None:
            if not isinstance(public_key, (bytes, bytearray)) or bytes(public_key) != secret[32:64]:
                raise ValueError("cache public key differs from the signing secret key")
        if cache_path is not None:
            if public_key is None:
                raise ValueError("cache_load requires the matching 32-byte public key")
            encoded_path = os.fsencode(cache_path)
            if b"\x00" in encoded_path:
                raise ValueError("cache path contains a NUL byte")
        native = self._native()
        try:
            native.bind_key(secret)
            if level is not None:
                native.set_cache_level(level)
            if cache_path is not None:
                if public_key is None or len(bytes(public_key)) != self.public_key_bytes:
                    raise ValueError("cache_load requires the matching 32-byte public key")
                native.cache_load(str(cache_path), bytes(public_key))
        except BaseException:
            native.close()
            raise
        previous = self._signing_contexts.pop(secret, None)
        if previous is not None:
            previous.close()
        self._signing_contexts[secret] = native
        self._cache_ready.discard(secret)
        if cache_path is not None:
            self._cache_ready.add(secret)
        self.last_cache = {"mode": "loaded" if cache_path is not None else "bound",
                           "path": str(cache_path) if cache_path is not None else None,
                           "algorithm": self.name, "backend": native.backend,
                           "library_path": str(Path(native.library_path).resolve()),
                           "threads": self.threads}
        return native

    def cache_build(self, secret_key: object, level: int, *, save_path=None,
                    public_key: bytes | None = None):
        """Explicitly build (and optionally persist) a cache for offline CA use."""
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 64:
            raise ValueError("SLH secret key must contain 64 bytes")
        secret = bytes(secret_key)
        if public_key is not None:
            if not isinstance(public_key, (bytes, bytearray)) or bytes(public_key) != secret[32:64]:
                raise ValueError("cache public key differs from the signing secret key")
        if save_path is not None and b"\x00" in os.fsencode(save_path):
            raise ValueError("cache path contains a NUL byte")
        native = self._signing_contexts.get(secret) or self._native()
        owned = secret not in self._signing_contexts
        self._cache_ready.discard(secret)
        try:
            native.bind_key(secret)
            native.cache_build(secret, level)
            if save_path is not None:
                native.cache_save(str(save_path))
        except BaseException:
            if owned:
                native.close()
            raise
        if owned:
            self._signing_contexts[secret] = native
        self._cache_ready.add(secret)
        self.last_cache = {"mode": "built", "level": level,
                           "path": str(save_path) if save_path is not None else None,
                           "algorithm": self.name, "backend": native.backend,
                           "library_path": str(Path(native.library_path).resolve()),
                           "threads": self.threads}
        return native

    def close(self):
        for native in self._signing_contexts.values():
            native.close()
        self._signing_contexts.clear()
        self._cache_ready.clear()

    def __del__(self):
        if hasattr(self, "_signing_contexts"):
            self.close()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify one signature, distinguishing bad input from a broken backend.

        A signature that does not match, or a well-formed but malformed encoding,
        returns ``False``. A missing library, ABI mismatch, execution failure or a
        missing independent-model dependency raises :class:`BackendUnavailableError`
        so ``require_native`` cannot be silently reported as a normal mismatch.
        """
        self.last_verification = {"mode": "rejected-input", "algorithm": self.name}
        if (not isinstance(public_key, (bytes, bytearray))
                or not isinstance(message, (bytes, bytearray))
                or not isinstance(signature, (bytes, bytearray))):
            return False
        public_key = bytes(public_key)
        message = bytes(message)
        signature = bytes(signature)
        if len(public_key) != self.public_key_bytes or len(signature) != self.signature_bytes:
            return False
        backend_failure: BackendUnavailableError | None = None
        if not self.force_python:
            try:
                native = self._native()
            except BackendUnavailableError as error:
                backend_failure = error
                if self.require_native:
                    raise
            else:
                try:
                    with native:
                        path = Path(native.library_path).resolve()
                        before = hashlib.sha256(path.read_bytes()).hexdigest()
                        result = bool(native.verify(message, signature, public_key, context=b""))
                        if hashlib.sha256(path.read_bytes()).hexdigest() != before:
                            raise BackendUnavailableError("native library changed during verification")
                        self.last_verification = {"mode": "native", "algorithm": self.name,
                            "library_path": str(path), "library_sha256": before,
                            "native_adapter_path": str((PROJECT_ROOT / "tools/native.py").resolve()),
                            "backend": native.backend, "threads": self.threads, "passed": result}
                        return result
                except BackendUnavailableError:
                    raise
                except (RuntimeError, OSError, AttributeError) as error:
                    raise BackendUnavailableError(
                        f"SLH native execution failed: {type(error).__name__}: {error}"
                    ) from error
        try:
            self._modules()
            reference = self._local_module("reference/__init__.py", "reference")
            with reference.ReferenceSlhDsa(self.pid, workers=1) as model:
                result = bool(model.verify(message, signature, public_key, context=b""))
        except BackendUnavailableError:
            raise
        except (ImportError, OSError) as error:
            detail = f"SLH independent Python model unavailable: {type(error).__name__}: {error}"
            if backend_failure is not None:
                detail += f" (native backend also unavailable: {backend_failure})"
            raise BackendUnavailableError(detail) from error
        except (ValueError, TypeError, IndexError) as error:
            self.last_verification = {"mode": "python", "algorithm": self.name,
                                      "passed": False, "reason": str(error)}
            return False
        except RuntimeError as error:
            raise BackendUnavailableError(
                f"SLH independent Python model failed: {type(error).__name__}: {error}"
            ) from error
        self.last_verification = {"mode": "python", "algorithm": self.name, "passed": result,
                                  "reference_model_path": str((PROJECT_ROOT / "reference/slhdsa.py").resolve())}
        return result
