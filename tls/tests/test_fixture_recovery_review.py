"""Recovery regressions: temporary SQLite ledgers, fake PQ, real small EC/X.509."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

PROJECT = next(p for p in Path(__file__).resolve().parents
               if (p / "tools/alt_chain_fixtures.py").is_file())
sys.path.insert(0, str(PROJECT))
sys.path.insert(0, str(PROJECT / "base_tls"))
spec = importlib.util.spec_from_file_location("fixture_recovery_generator", PROJECT / "tools/alt_chain_fixtures.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
from tls import alt_chain
from tools.signing_budget import SigningBudget


class FakePQ:
    """Intentionally not cryptographic; never calls a native library or PQ tree."""
    name = "ml-dsa-44"
    public_key_bytes = signature_bytes = 32

    def __init__(self):
        self.counter = 0

    def keygen(self):
        self.counter += 1
        public = bytes([self.counter]) * 32
        return public * 2, public

    def sign(self, secret, message):
        return hashlib.sha256(secret[-32:] + message).digest()

    def verify(self, public, message, signature):
        return signature == hashlib.sha256(public + message).digest()


class FixtureRecoveryReview(unittest.TestCase):
    algorithm = "ml-dsa-44"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fixture-recovery-review-")
        self.addCleanup(temporary.cleanup)
        self.folder = Path(temporary.name)
        self.library = self.folder / "fake-library"
        self.library.write_bytes(b"unit-only: no library is loaded")
        self.args = SimpleNamespace(output=self.folder / "published", library=self.library,
            budget_db=self.folder / "ledger.sqlite", test_only_no_budget=False,
            algorithm=[self.algorithm], resume=None, handshake_signer="review-fake-handshake",
            threads=1, backend=1, ca_cache_dir=None, ca_cache_level=6)
        self.builder_calls = self.handshake_keygens = self.ec_keygens = 0
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(fixtures, "get_pq_signer", side_effect=self.handshake))
        self.stack.enter_context(patch.object(alt_chain, "get_alt_signer", side_effect=lambda *a, **k: FakePQ()))
        self.stack.enter_context(patch.object(fixtures.ec, "generate_private_key", side_effect=self.small_ec_key))
        self.stack.enter_context(patch.object(fixtures, "build_alt_test_chain", side_effect=self.build))

    def handshake(self, *a, **k):
        def keygen():
            self.handshake_keygens += 1
            return b"fake-handshake-secret", b"h" * 32
        return SimpleNamespace(name=self.args.handshake_signer, scheme_id=1, keygen=keygen)

    def small_ec_key(self, *a, **k):
        self.ec_keygens += 1
        return ec.derive_private_key(self.ec_keygens, ec.SECP256R1())

    def build(self, *a, **k):
        self.builder_calls += 1
        return alt_chain.build_alt_test_chain(*a, **k)

    def used(self):
        return sum(row["used"] for row in SigningBudget(self.args.budget_db).status())

    def stage(self):
        return next(self.folder.glob(".published.staging-*"))

    def interrupt(self, phase):
        replace = fixtures.os.replace
        update = fixtures._replace_json
        def renamed(source, destination):
            destination = Path(destination)
            hit = ((phase == "complete-work" and destination.name == self.algorithm) or
                   # The generator resolves output paths; Windows TEMP can use
                   # an 8.3 alias for that same directory on hosted runners.
                   (phase in ("manifest", "after-final-rename") and
                    destination.resolve() == self.args.output.resolve()))
            if hit and phase != "after-final-rename":
                raise KeyboardInterrupt("injected publication interruption")
            result = replace(source, destination)
            if hit:
                raise KeyboardInterrupt("injected after final rename")
            return result
        def updated(path, value):
            if phase == "algorithm-rename" and path.name == "campaign.json" and value.get("completed"):
                raise KeyboardInterrupt("injected before campaign completion update")
            return update(path, value)
        with patch.object(fixtures.os, "replace", side_effect=renamed), \
             patch.object(fixtures, "_replace_json", side_effect=updated), \
             self.assertRaises(KeyboardInterrupt):
            fixtures.generate(self.args)
        if phase == "after-final-rename":
            campaign = json.loads((self.args.output / "campaign.json").read_text())
            self.args.resume = Path(campaign["staging_path"])
        else:
            self.args.resume = self.stage()
        self.assertEqual(self.used(), 2)

    def assert_resumes_without_signing(self):
        before = self.builder_calls, self.handshake_keygens, self.ec_keygens
        fixtures.generate(self.args)
        self.assertEqual((self.builder_calls, self.handshake_keygens, self.ec_keygens), before)
        self.assertEqual(self.used(), 2)
        self.assertTrue((self.args.output / "MANIFEST.json").is_file())

    def metadata(self):
        path = self.stage() / self.algorithm / "fixture.json"
        return path, json.loads(path.read_text())

    def test_complete_work_resumes_without_resigning(self):
        self.interrupt("complete-work")
        self.assert_resumes_without_signing()

    def test_algorithm_rename_before_completion_update_recovers(self):
        self.interrupt("algorithm-rename")
        self.assert_resumes_without_signing()

    def test_manifest_before_final_rename_recovers(self):
        self.interrupt("manifest")
        self.assert_resumes_without_signing()

    def test_manifest_interruption_handles_noncanonical_output_path(self):
        alias = self.folder / "path-alias"
        alias.mkdir()
        self.args.output = alias / ".." / "published"
        self.interrupt("manifest")
        self.assert_resumes_without_signing()

    def test_final_rename_before_success_message_recovers(self):
        self.interrupt("after-final-rename")
        self.assert_resumes_without_signing()

    def test_completed_output_can_be_explicitly_reconciled(self):
        fixtures.generate(self.args)
        self.args.resume = self.args.output
        self.assert_resumes_without_signing()

    def test_duplicate_generation_without_resume_is_refused(self):
        fixtures.generate(self.args)
        with self.assertRaisesRegex(ValueError, "already exists"):
            fixtures.generate(self.args)
        self.assertEqual(self.builder_calls, 1)
        self.assertEqual(self.used(), 2)

    def test_incomplete_charged_work_never_resigns(self):
        def interrupted(*a, **k):
            self.build(*a, **k)
            raise KeyboardInterrupt("after signing, before serializing files")
        with patch.object(fixtures, "build_alt_test_chain", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            fixtures.generate(self.args)
        self.args.resume = self.stage()
        before = self.builder_calls, self.handshake_keygens
        with self.assertRaisesRegex(RuntimeError, "refusing to re-sign"):
            fixtures.generate(self.args)
        self.assertEqual((self.builder_calls, self.handshake_keygens), before)
        self.assertEqual(self.used(), 2)

    def test_completed_missing_file_is_rejected(self):
        self.interrupt("manifest")
        (self.stage() / self.algorithm / "leaf.der").unlink()
        with self.assertRaisesRegex(ValueError, "file missing"):
            fixtures.generate(self.args)
        self.assertFalse(self.args.output.exists())
        self.assertEqual(self.used(), 2)

    def test_completed_changed_file_is_rejected(self):
        self.interrupt("manifest")
        (self.stage() / self.algorithm / "leaf.der").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "hash differs"):
            fixtures.generate(self.args)
        self.assertFalse(self.args.output.exists())

    def test_missing_required_hash_is_rejected(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        del metadata["files_sha256"]["root-test-key.pem"]
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(ValueError, "required file hashes"):
            fixtures.generate(self.args)

    def test_path_escape_is_rejected_before_reading(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        metadata["files_sha256"]["../outside"] = "0" * 64
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(ValueError, "outside bundle"):
            fixtures.generate(self.args)

    def test_replacement_ledger_is_rejected(self):
        self.interrupt("manifest")
        original = self.args.budget_db
        self.args.budget_db = self.folder / "new-ledger.sqlite"
        with self.assertRaisesRegex(ValueError, "ledger UUID differs"):
            fixtures.generate(self.args)
        self.assertEqual(self.used(), 0)
        self.assertEqual(sum(row["used"] for row in SigningBudget(original).status()), 2)
        self.assertFalse(self.args.output.exists())

    def test_legacy_campaign_still_checks_fixture_ledger(self):
        self.interrupt("manifest")
        path = self.stage() / "campaign.json"
        campaign = json.loads(path.read_text())
        del campaign["budget_ledger_uuid"]
        fixtures._replace_json(path, campaign)
        self.args.budget_db = self.folder / "new-ledger.sqlite"
        with self.assertRaisesRegex(ValueError, "ledger UUID differs"):
            fixtures.generate(self.args)

    def test_legacy_partial_campaign_cannot_change_ledger_and_resign(self):
        self.interrupt("manifest")
        stage = self.stage()
        path = stage / "campaign.json"
        campaign = json.loads(path.read_text())
        del campaign["budget_ledger_uuid"]
        campaign["completed"] = []
        fixtures._replace_json(path, campaign)
        # Remove only files in this isolated fixture temporary directory. The
        # original charged ledger is deliberately retained and never refunded.
        import shutil
        shutil.rmtree(stage / self.algorithm)
        (stage / "MANIFEST.json").unlink()
        self.args.budget_db = self.folder / "new-ledger.sqlite"
        with self.assertRaisesRegex(ValueError, "legacy campaign lacks"):
            fixtures.generate(self.args)
        self.assertEqual(self.builder_calls, 1)
        self.assertEqual(self.used(), 0)
        self.assertFalse(self.args.output.exists())

    def test_budgeted_fixture_cannot_be_resumed_without_ledger(self):
        self.interrupt("manifest")
        self.args.budget_db = None
        self.args.test_only_no_budget = True
        with self.assertRaisesRegex(ValueError, "ledger UUID differs"):
            fixtures.generate(self.args)

    def test_missing_receipt_is_rejected(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        metadata["signing_records"][0]["budget_receipt"] = "missing"
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(RuntimeError, "receipt missing"):
            fixtures.generate(self.args)

    def test_committed_receipt_for_another_message_is_rejected(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        row = metadata["signing_records"][0]
        ledger = SigningBudget(self.args.budget_db)
        row["budget_receipt"] = ledger.reserve(self.algorithm, b"different-public-key",
            b"another-message", operation_id="other-operation", case_identity="other-case")
        ledger.finish(row["budget_receipt"], b"another-signature")
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(RuntimeError, "differs"):
            fixtures.generate(self.args)
        self.assertFalse(self.args.output.exists())
        self.assertEqual(self.used(), 3)

    def test_valid_ledger_record_must_match_verified_certificate_edge(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        row = metadata["signing_records"][0]
        row["pre_tbs_sha256"] = "0" * 64
        fixtures._replace_json(path, metadata)
        ledger = SigningBudget(self.args.budget_db)
        original_validate = SigningBudget.validate_receipt
        # Simulate a preserved committed record that passed the ledger check,
        # then require the real certificate verifier to independently reject its
        # different message digest. No alternate certificate is signed.
        def accepted_record(instance, receipt, **kwargs):
            if receipt == row["budget_receipt"]:
                kwargs.pop("message_sha256", None)
            return original_validate(instance, receipt, **kwargs)
        with patch.object(SigningBudget, "validate_receipt", accepted_record), \
             self.assertRaisesRegex(ValueError, "verified certificate edge differs"):
            fixtures.generate(self.args)
        self.assertEqual(ledger.reconcile()["reservations"], 2)
        self.assertFalse(self.args.output.exists())

    def test_pre_tbs_file_must_match_certificate_even_if_its_hash_is_updated(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        filename = "leaf-pre-tbs.der"
        (path.parent / filename).write_bytes(b"different preTBS")
        metadata["files_sha256"][filename] = fixtures.sha(b"different preTBS")
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(ValueError, "preTBS differs"):
            fixtures.generate(self.args)
        self.assertFalse(self.args.output.exists())

    def test_reserved_unfinished_operation_is_not_retried(self):
        def reserved(*a, **kwargs):
            operation = kwargs["operation_prefix"] + ":intermediate"
            kwargs["before_sign"](self.algorithm, b"p" * 32, b"preTBS",
                operation_id=operation, case_identity=operation)
            raise KeyboardInterrupt("after durable reserve")
        with patch.object(fixtures, "build_alt_test_chain", side_effect=reserved), \
             self.assertRaises(KeyboardInterrupt):
            fixtures.generate(self.args)
        self.args.resume = self.stage()
        before = self.handshake_keygens
        with self.assertRaisesRegex(RuntimeError, "status reserved.*refusing to re-sign"):
            fixtures.generate(self.args)
        self.assertEqual(self.handshake_keygens, before)
        self.assertEqual(self.used(), 1)

    def test_duplicate_signing_record_is_rejected(self):
        self.interrupt("manifest")
        path, metadata = self.metadata()
        metadata["signing_records"][1] = metadata["signing_records"][0]
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(ValueError, "exactly two"):
            fixtures.generate(self.args)

    def test_manifest_campaign_mismatch_is_rejected(self):
        self.interrupt("manifest")
        path = self.stage() / "MANIFEST.json"
        metadata = json.loads(path.read_text())
        metadata["operation_prefix"] = "another-campaign"
        fixtures._replace_json(path, metadata)
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            fixtures.generate(self.args)

    def test_library_change_is_rejected(self):
        self.interrupt("manifest")
        self.library.write_bytes(b"changed library")
        with self.assertRaisesRegex(ValueError, "provenance"):
            fixtures.generate(self.args)

    def test_explicit_no_budget_test_mode_still_recovers(self):
        self.args.budget_db = None
        self.args.test_only_no_budget = True
        fixtures.generate(self.args)
        self.args.resume = self.args.output
        fixtures.generate(self.args)
        self.assertEqual(self.builder_calls, 1)
        self.assertEqual(self.handshake_keygens, 1)

    def test_source_hashes_include_real_tls_and_ledger(self):
        hashes = fixtures.source_hashes()
        prefix = "base_tls/" if (PROJECT / "base_tls/tls").is_dir() else ""
        self.assertIn(prefix + "tls/alt_chain.py", hashes)
        self.assertIn(prefix + "tls/pq/slhdsa_sm3.py", hashes)
        self.assertIn("tools/signing_budget.py", hashes)

    def test_file_contents_are_synced_before_success(self):
        with patch.object(fixtures.os, "fsync", wraps=fixtures.os.fsync) as sync:
            fixtures.write(self.folder / "artifact", b"public-only")
        self.assertGreaterEqual(sync.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
