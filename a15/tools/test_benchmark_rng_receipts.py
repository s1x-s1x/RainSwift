"""RNG keygen evidence must account for its additional validation signature."""
import copy
import unittest
from unittest.mock import patch

from tools import test_budget_repair as helpers
cpu, SigningBudget = helpers.cpu, helpers.SigningBudget


class RngReceipts(unittest.TestCase):
    def setUp(self):
        self.helper = helpers.BudgetRepair()
        self.helper.setUp()
        self.addCleanup(self.helper.temp.cleanup)
        self.budget, _, self.rows = self.helper.evidence()
        self.case = cpu.case_record(201, "keygen", cache="10", keygen="rng", samples=1, family="rng-receipt-regression")
        self.inputs = {"pk": self.helper.public, "message": b"m", "context": b"c"}
        self.public = b"R" * 32
        self.secret = b"S" * 32 + self.public
        self.sample = self.rows[3]
        self.operation = self.sample["operation_id"]
        self.case_key = self.sample["case_key"]
        self.ready = {"kind": "inputs_ready", "ledger_uuid": self.budget.ledger_uuid,
                      "input_hashes": {k: cpu.sha(v) for k, v in self.inputs.items()},
                      "budget_binding": cpu.budget_binding(self.budget, self.case, self.inputs)}

    def validation(self, verifier, record=None):
        return cpu.validate_result(verifier, self.case, self.inputs, (self.public, self.secret), self.budget,
                                   operation_id=self.operation, case_identity=self.case_key,
                                   validation_record=record)

    def test_passed_rng_samples_and_warmups_require_live_receipts(self):
        class Verifier:
            def sign(self, *args): return b"synthetic-test-signature"
            def verify(self, *args): return True
        valid = self.validation(Verifier())
        for kind in ("sample", "warmup"):
            row = {**self.sample, "kind": kind, "receipt": None, "budget_evidence": None, "validation": valid}
            cpu.validate_preserved_budget([self.ready, row], self.case, self.budget)
            for damaged in (None, {}, {"timed": False}, {"rng_validation_receipt": "missing"}):
                with self.subTest(kind=kind, validation=damaged):
                    altered = {**row, "validation": damaged}
                    with self.assertRaises(ValueError):
                        cpu.validate_preserved_budget([self.ready, altered], self.case, self.budget)
            for field in ("operation_id", "case_identity", "public_key_sha256", "message_sha256", "signature_sha256"):
                altered = copy.deepcopy(row)
                altered["validation"]["budget_evidence"][field] = "0" * 64
                with self.subTest(field=field), self.assertRaises(ValueError):
                    cpu.validate_preserved_budget([self.ready, altered], self.case, self.budget)

    def test_failed_rng_validation_keeps_charge_and_receipt_in_worker_record(self):
        for failure in (ValueError("injected sign failure"), KeyboardInterrupt("injected cancellation")):
            # Each operation gets its own identity; a failed reservation stays consumed.
            self.operation += ":next"
            class Verifier:
                def sign(self, *args): raise failure
            record = {}
            with self.assertRaises(type(failure)) as caught:
                self.validation(Verifier(), record)
            self.assertIs(caught.exception, failure)
            self.assertEqual(record["budget_evidence"]["status"], "failed")
            self.assertEqual(record["budget_evidence"]["operation_id"], self.operation + ":rng")
            self.budget.validate_receipt(record["rng_validation_receipt"], statuses=("failed",))
            failed_row = {**self.sample, "operation_id": self.operation, "passed": False,
                          "receipt": None, "budget_evidence": None, "validation": record}
            cpu.validate_preserved_budget([self.ready, failed_row], self.case, self.budget)
        charged = next(row for row in self.budget.status() if row["key_id"] == SigningBudget.key_id(cpu.ALGORITHMS[201], self.public))
        self.assertEqual(charged["used"], 2)

    def test_ledger_finalizer_failure_preserves_primary_and_reserved_receipt(self):
        original = ValueError("injected primary failure")
        class Verifier:
            def sign(self, *args): raise original
        record = {}
        with patch.object(self.budget, "finish", side_effect=RuntimeError("injected finalizer failure")):
            with self.assertRaises(ValueError) as caught:
                self.validation(Verifier(), record)
        self.assertIs(caught.exception, original)
        self.assertEqual(record["budget_evidence"]["status"], "reserved")
        self.assertTrue(any("finalization also failed" in note for note in original.__notes__))
        self.assertTrue(record["rng_validation_receipt"])


if __name__ == "__main__":
    unittest.main()
