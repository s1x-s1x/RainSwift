"""Reject accepted audit metadata from another dataset or altered raw rows."""
import json
from pathlib import Path
import tempfile
import unittest
from tools.package_local_lifecycle import audit_bindings, sha


class LifecyclePackageBindingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.campaign = self.root / "campaign"
        self.prefix, self.independent = self.root / "prefix", self.root / "independent"
        for path in (self.campaign / "keygen", self.prefix, self.independent):
            path.mkdir(parents=True)
        self.build = self.root / "accepted-build.json"
        self.build.write_text("{}")
        (self.campaign / "plan.json").write_text("{}")
        (self.campaign / "campaign.json").write_text(json.dumps({"steps": [{"phase": "keygen"}]}))
        (self.campaign / "budget.sqlite").write_bytes(b"binding-only ledger fixture")
        (self.campaign / "keygen/timing.jsonl").write_text('{"binding_only":true}\n')
        self.p = {"status": "PASS_COMPLETED_PREFIX_ONLY", "plan_sha256": sha(self.campaign / "plan.json"),
                  "campaign_sha256": sha(self.campaign / "campaign.json"), "build_manifest_sha256": sha(self.build),
                  "ledger": {"database_sha256": sha(self.campaign / "budget.sqlite")}}
        self.i = {"passed": True, "plan_sha256": self.p["plan_sha256"],
                  "build_manifest_sha256": self.p["build_manifest_sha256"],
                  "database_sha256": self.p["ledger"]["database_sha256"], "run_root": "X:\\original",
                  "audited_files_sha256": {"X:\\original\\" + name.replace("/", "\\"): sha(self.campaign / name)
                    for name in ("plan.json", "campaign.json", "budget.sqlite", "keygen/timing.jsonl")}}
        self.write()

    def write(self):
        (self.prefix / "audit.json").write_text(json.dumps(self.p))
        (self.independent / "audit.json").write_text(json.dumps(self.i))

    def check(self):
        return audit_bindings(self.campaign, self.build, self.prefix, self.independent)

    def test_matching_bindings_accepted(self):
        self.assertEqual(self.check()["independent_campaign_files_checked"], 4)

    def test_other_accepted_campaign_rejected(self):
        self.p["campaign_sha256"] = "0" * 64
        self.write()
        with self.assertRaisesRegex(ValueError, "another plan/campaign"):
            self.check()

    def test_unchanged_plan_with_altered_raw_rows_rejected(self):
        (self.campaign / "keygen/timing.jsonl").write_text("altered raw rows\n")
        with self.assertRaisesRegex(ValueError, "audited campaign input differs"):
            self.check()

    def test_missing_campaign_attestation_rejected(self):
        del self.i["audited_files_sha256"]["X:\\original\\campaign.json"]
        self.write()
        with self.assertRaisesRegex(ValueError, "lacks campaign/raw bindings"):
            self.check()


if __name__ == "__main__":
    unittest.main()
