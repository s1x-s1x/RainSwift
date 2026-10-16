"""Server credentials and the modelled certificate authority.

The certificate authority is a classical signer that signs the hybrid certificate
body. Modelling it explicitly is what keeps the scope honest: this paper's subject
is how the handshake carries post-quantum material, not how a post-quantum X.509
hierarchy is operated. The client trusts one CA public key out of band, exactly as
it would trust a root store.
"""

from __future__ import annotations

from dataclasses import dataclass

from .classical.signature import ClassicalSigner, EcdsaP256Sha256
from .config import HybridTLSConfig
from .errors import HybridTLSError
from .handshake.messages import HybridCertificateBody
from .pki import CertificateChain, build_test_chain
from .pq.backends import PqSigner

__all__ = ["CertificateAuthority", "ServerCredentials"]


class CertificateAuthority:
    """A single-key test CA that issues hybrid certificates."""

    def __init__(self, signer: ClassicalSigner, name: bytes = b"hybrid-tls13 test CA") -> None:
        self.signer = signer
        self.secret_key, self.public_key = signer.keygen()
        self.name = name

    def issue(self, body: HybridCertificateBody) -> bytes:
        """Sign a certificate body."""
        return self.signer.sign(self.secret_key, self.name + body.encode())

    def verify(self, body: HybridCertificateBody, signature: bytes) -> bool:
        """Verify a certificate signature."""
        return self.signer.verify(self.public_key, self.name + body.encode(), signature)


class ServerCredentials:
    """The server's classical and post-quantum authentication key pairs."""

    def __init__(
        self,
        config: HybridTLSConfig,
        identity: bytes = b"server.example",
        classical_signer: ClassicalSigner | None = None,
        pq_signer: PqSigner | None = None,
    ) -> None:
        self.config = config
        self.identity = identity
        self.classical_signer = classical_signer or config.classical()
        self.classical_secret, self.classical_public = self.classical_signer.keygen()
        if config.pq_enabled:
            self.pq_signer: PqSigner | None = pq_signer or config.pq()
            self.pq_secret, self.pq_public = self.pq_signer.keygen()
        else:
            # The classical-only baseline never generates a post-quantum key pair, so
            # its wall time does not include one -- for XMSS that would be half a second.
            self.pq_signer = pq_signer
            self.pq_secret, self.pq_public = None, None
        self.chain = self._build_chain() if config.x509 else None

    def _build_chain(self) -> CertificateChain:
        """Build a real X.509 chain whose leaf certifies this server's own keys."""
        if not isinstance(self.classical_signer, EcdsaP256Sha256):
            raise HybridTLSError(
                "the X.509 profile certifies an ECDSA P-256 key, so "
                f"{self.classical_signer.name} cannot be used with x509=True"
            )
        return build_test_chain(
            self.identity.decode(),
            leaf_key=self.classical_secret,
            pq_scheme_id=self.pq_signer.scheme_id if self.pq_signer is not None else None,
            pq_public_key=self.pq_public,
        )

    def certificate_body(self) -> HybridCertificateBody:
        """Build the certified body binding both public keys to one identity."""
        return HybridCertificateBody(
            server_identity=self.identity,
            classical_scheme=self.classical_signer.scheme_id,
            classical_public_key=self.classical_public,
            pq_scheme=self.pq_signer.scheme_id if self.pq_signer is not None else None,
            pq_public_key=self.pq_public,
        )

    def bind_to(self, authority: CertificateAuthority) -> "IssuedCertificate":
        """Have ``authority`` issue the certificate for these credentials."""
        body = self.certificate_body()
        return IssuedCertificate(body=body, authority=authority, signature=authority.issue(body))

    def pq_signatures_remaining(self) -> int | None:
        """Remaining one-time signatures for stateful backends, else ``None``."""
        if self.pq_signer is None:
            return None
        remaining = getattr(self.pq_signer, "max_signatures", None)
        if remaining is None:
            return None
        used = getattr(self.pq_secret, "next_index", 0)
        return int(remaining) - int(used)


@dataclass
class IssuedCertificate:
    """A hybrid certificate plus the CA signature over it.

    Two validating methods were removed from this class after `tools/audit_live_checks.py`
    found them: `verify()` was called **only** from a test, and `require_valid()` from
    nothing at all. Neither is on the handshake path — the client verifies the CA signature
    itself in ``HybridClient._check_modelled_certificate``, and checks the scheme there too.
    A second, unexercised copy of a security check reads like coverage without being any,
    which is the defect three reviews have each found in this repository in a different
    place. The tests now call the authority directly, so the assertion is unchanged.
    """

    body: HybridCertificateBody
    authority: CertificateAuthority
    signature: bytes
