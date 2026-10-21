"""Real SQLite failures around finalization; no native signing calls."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing_budget import SigningBudget
from bench_local_lifecycle import settle_signing_attempt
from audit_local_lifecycle import audit_ledger


class LifecycleSettlementTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "budget.sqlite"
        self.ledger = SigningBudget(self.path)
        self.pk, self.message, self.candidate = bytes(range(32)), b"message", b"candidate output"
        self.operation, self.case = "test-operation", "sign_uncached:wots0-fors0"
        self.receipt = self.ledger.reserve("SLH-DSA-SM3-128-24", self.pk, self.message,
                                         operation_id=self.operation, case_identity=self.case)
        self.row = {"passed": True, "receipt": self.receipt, "operation_id": self.operation,
                    "phase": "sign_uncached", "variant": "wots0-fors0",
                    "result_signature_sha256": hashlib.sha256(self.candidate).hexdigest()}

    def block_finalization(self):
        with self.ledger.connection() as db:
            db.execute("CREATE TRIGGER injected_failure BEFORE UPDATE ON reservations "
                       "BEGIN SELECT RAISE(ABORT,'injected failure before commit'); END")

    def settle(self, error=None):
        return settle_signing_attempt(self.ledger, self.receipt, self.candidate, self.pk,
            self.message, self.operation, self.case, self.row, error)

    def reconcile_and_audit(self, expected_status):
        with self.ledger.connection() as db:
            db.execute("DROP TRIGGER IF EXISTS injected_failure")
        self.assertTrue(self.ledger.reconcile()["reconciled"])
        self.assertEqual(self.ledger.status()[0]["used"], 1)
        with self.ledger.connection() as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        result = audit_ledger(self.path, [self.row], self.pk, self.message, self.candidate)
        self.assertEqual(result["receipt_status_counts"], {expected_status: 1})

    def test_sql_failure_preserves_reserved_receipt_and_candidate(self):
        self.block_finalization()
        error = self.settle()
        self.assertIsNotNone(error)
        self.assertFalse(self.row["passed"])
        self.assertFalse(self.row["timing_accepted"])
        self.assertEqual(self.row["receipt_evidence"]["status"], "reserved")
        self.assertIsNone(self.row["receipt_persisted_signature_sha256"])
        self.assertEqual(self.row["candidate_signature_sha256"], hashlib.sha256(self.candidate).hexdigest())
        self.assertNotIn("receipt_validation_error", self.row)
        self.reconcile_and_audit("reserved")

    def test_exception_after_real_commit_keeps_actual_committed_state(self):
        finish = self.ledger.finish
        def after_commit(receipt, signature):
            finish(receipt, signature)
            raise OSError("injected exception after commit")
        with patch.object(self.ledger, "finish", side_effect=after_commit):
            self.assertIsInstance(self.settle(), OSError)
        self.assertFalse(self.row["passed"])
        self.assertEqual(self.row["receipt_evidence"]["status"], "committed")
        self.assertEqual(self.row["receipt_persisted_signature_sha256"], self.row["candidate_signature_sha256"])
        self.reconcile_and_audit("committed")

    def test_primary_failure_remains_primary(self):
        self.block_finalization()
        primary = ValueError("oracle failure")
        self.row["passed"] = False
        self.assertIs(self.settle(primary), primary)
        self.assertEqual(self.row["error"], repr(primary))
        self.assertTrue(primary.__notes__)
        self.reconcile_and_audit("reserved")


if __name__ == "__main__":
    unittest.main()
