"""Synthetic analyzer negatives, not GPU or product runtime evidence."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "gpu_cadence", Path(__file__).resolve().parents[2] / "scripts/network-rewrite-gpu-cadence.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture():
    return {
        "scope": "receiver-only-live-product", "latest_terminal_origin": "observed-in-this-recorder",
        "scanout_verified": False,
        "latest_terminal": {"receiver": {
            "generation": 1, "width": 1920, "height": 1080,
            "worker_started": True, "decoder_opened": True, "worker_joined": True,
            "revoked": True, "failed": False, "worker_panicked": False,
            "terminal_write_failed": False, "terminal_write_pending": False,
            "accepted": 3601, "decoded": 3601, "converted": 3601, "submitted": 3601,
            "qpc_frequency": 60_000,
            "submission_cadence": {"frame_count": 3601, "first_qpc": 0,
                "last_qpc": 3_600_000, "invalid_timestamps": 0,
                "recent_qpc": list(range(3_089_000, 3_600_001, 1000))},
        }},
    }


class CadenceTests(unittest.TestCase):
    def test_exact_integer_gate_preserves_measurement_boundary(self):
        result = MODULE.inspect(fixture())
        self.assertEqual(result["lifetime_duration_seconds"], 60)
        self.assertEqual(result["lifetime_fps"], 60)
        self.assertTrue(result["lifetime_at_least_60_seconds"])
        self.assertTrue(result["recent_interval_p95_at_most_25_ms"])
        self.assertFalse(result["full_lifetime_p95_available"])
        self.assertFalse(result["AC54_passed"])
        self.assertFalse(result["scanout_verified"])

    def test_clock_owner_history_and_cleanup_negatives(self):
        changes = [
            ("frame_count", 3600), ("invalid_timestamps", 1), ("last_qpc", 3_600_001),
            ("recent_qpc", [1, 1]), ("recent_qpc", list(range(513))),
        ]
        for field, value in changes:
            report = fixture()
            report["latest_terminal"]["receiver"]["submission_cadence"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE.inspect(report)
        for field, value in [("worker_joined", False), ("revoked", False),
                             ("failed", True), ("terminal_write_pending", True),
                             ("qpc_frequency", 0), ("submitted", True)]:
            report = fixture()
            report["latest_terminal"]["receiver"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                MODULE.inspect(report)
        report = fixture()
        report["latest_terminal_origin"] = "historical-disk-receipt"
        with self.assertRaises(ValueError):
            MODULE.inspect(report)

    def test_actual_slow_interval_tail_fails_the_original_threshold(self):
        report = fixture()
        cadence = report["latest_terminal"]["receiver"]["submission_cadence"]
        cadence["recent_qpc"] = [2_000_000 + i * 2000 for i in range(512)]
        cadence["last_qpc"] = cadence["recent_qpc"][-1]
        result = MODULE.inspect(report)
        self.assertFalse(result["recent_interval_p95_at_most_25_ms"])
        self.assertAlmostEqual(result["recent_interval_p95_ms"], 100 / 3)


if __name__ == "__main__":
    unittest.main()
