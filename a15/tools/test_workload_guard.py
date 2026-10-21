"""Real process-lock exclusion and process-tree checks, without native calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.workload_guard import native_competitors, performance_exclusive


class WorkloadGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_real_subprocess_lock_is_exclusive_and_released(self):
        code = ("from tools.workload_guard import performance_exclusive; import sys; "
                "guard=performance_exclusive(sys.argv[1], 'child'); guard.__enter__(); "
                "print('held', flush=True); sys.stdin.readline(); guard.__exit__(None,None,None)")
        # Only lock exclusion is tested here. The child skips the host workload
        # scan so this regression can run inside an active functional gate.
        code = "import tools.workload_guard as w; w.require_quiet=lambda:None; " + code
        child = subprocess.Popen([sys.executable, "-B", "-c", code, str(self.root)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "held")
            with self.assertRaisesRegex(RuntimeError, "holds the lock"):
                with performance_exclusive(self.root, "parent"):
                    self.fail("second process acquired held lock")
            stdout, stderr = child.communicate("release\n", timeout=10)
            self.assertEqual(child.returncode, 0, stderr + stdout)
            # A quiet function stub isolates release from host activity.
            from unittest.mock import patch
            with patch("tools.workload_guard.require_quiet"):
                with performance_exclusive(self.root, "after-release"):
                    self.assertTrue((self.root / "build/performance-workload.lock").is_file())
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)

    def fake_process(self, pid, parent, argv, state="R"):
        directory = self.root / str(pid)
        directory.mkdir()
        (directory / "cmdline").write_bytes(b"\0".join(x.encode() for x in argv) + b"\0")
        (directory / "status").write_text(f"Name:\tpython\nPPid:\t{parent}\nState:\t{state}\n")
        task = directory / "task" / str(pid)
        task.mkdir(parents=True)
        (task / "status").write_text(f"State:\t{state}\n")

    def test_network_lifecycle_and_functional_workloads_detected(self):
        for pid, script in enumerate(("check_kernel_network.py", "bench_local_lifecycle.py",
                                      "bootstrap_local_env.py", "check_optimization.py"), 20):
            self.fake_process(pid, 1, ["python", "-B", "tools/" + script])
        active = native_competitors(owner_pid=10, proc_root=self.root)
        self.assertEqual([row["pid"] for row in active], [20, 21, 22, 23])

    def test_owner_and_nested_workers_excluded(self):
        self.fake_process(10, 1, ["python", "tools/check_kernel_network.py", "run"])
        self.fake_process(11, 10, ["python", "tools/check_kernel_network.py", "client"])
        self.fake_process(12, 11, ["test_native"])
        self.fake_process(20, 1, ["python", "tools/bench_local_lifecycle.py"])
        self.assertEqual([r["pid"] for r in native_competitors(10, self.root)], [20])

    def test_stopped_workload_explicitly_observed_and_running_workload_rejected(self):
        self.fake_process(20, 1, ["python", "tools/check_optimization.py"], state="T")
        self.assertEqual(native_competitors(10, self.root), [])
        self.assertEqual(native_competitors(10, self.root, include_stopped=True)[0]["state"], "T")
        (self.root / "20/status").write_text("Name:\tpython\nPPid:\t1\nState:\tR\n")
        self.assertEqual(native_competitors(10, self.root)[0]["pid"], 20)

    def test_stopped_leader_with_running_thread_remains_a_competitor(self):
        self.fake_process(20, 1, ["python", "tools/check_optimization.py"], state="T")
        task = self.root / "20/task/21"
        task.mkdir()
        (task / "status").write_text("State:\tR\n")
        self.assertFalse(native_competitors(10, self.root)[0]["fully_stopped"])


if __name__ == "__main__":
    unittest.main()
