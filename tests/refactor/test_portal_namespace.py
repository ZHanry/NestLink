"""Ensure the native fixture cannot mount over the host's D-Bus directory."""
import importlib.util
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("portal_fixture", ROOT / "scripts/refactor-portal-capture.py")
PORTAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PORTAL)


class PortalNamespaceTests(unittest.TestCase):
    def test_privileged_launcher_maps_the_original_caller_and_preserves_arguments(self):
        child = ["/usr/bin/python3", "/private checkout/fixture.py", "--test-executable", "/private checkout/test"]
        with patch.object(PORTAL.os, "geteuid", return_value=1001, create=True), \
                patch.object(PORTAL.os, "getegid", return_value=118, create=True):
            command = PORTAL.namespace_command("sudo", child)
        self.assertEqual(command[:2], ["sudo", "-n"])
        self.assertEqual(command[command.index("--uid") + 1], "1001")
        self.assertEqual(command[command.index("--gid") + 1], "118")
        self.assertEqual(command[command.index("--") + 1:], child)
        self.assertNotIn("--map-root-user", command)
        self.assertEqual(PORTAL.namespace_command("unprivileged", child), [
            "unshare", "--user", "--map-root-user", "--mount", "--net",
            "--propagation", "private", *child])
        with self.assertRaises(ValueError):
            PORTAL.namespace_command("unknown", child)

    def test_group_leader_is_not_reaped_until_all_group_signals_finish(self):
        events = []
        child = SimpleNamespace(pid=123, returncode=None, wait=lambda **_: events.append("reap"))
        with patch.object(PORTAL.os, "getpgrp", return_value=100, create=True), \
                patch.object(PORTAL.os, "killpg", side_effect=lambda *args: events.append("signal"), create=True), \
                patch.object(PORTAL.signal, "SIGKILL", 9, create=True), \
                patch.object(PORTAL, "exited", return_value=True):
            PORTAL.stop_group(child)
            self.assertEqual(events, ["signal", "signal", "reap"])
            child.returncode = 0
            with self.assertRaises(RuntimeError):
                PORTAL.stop_group(child)
            self.assertEqual(events, ["signal", "signal", "reap"])

    def test_missing_partial_reused_or_host_namespaces_are_rejected(self):
        current = {name: name + ":[2]" for name in PORTAL.NAMESPACES}
        original = {name: name + ":[1]" for name in PORTAL.NAMESPACES}
        with patch.object(PORTAL, "namespaces", return_value=current), \
                patch.object(PORTAL.os, "geteuid", return_value=0, create=True):
            for invalid in ({}, {"mnt": "mnt:[1]"}, {**original, "net": current["net"]}, {**original, "extra": "extra:[1]"}):
                with self.assertRaises(RuntimeError):
                    PORTAL.isolated(invalid, original)
            PORTAL.isolated(original, original)
        # Different outer IDs do not bypass matching a saved host namespace.
        with patch.object(PORTAL, "namespaces", return_value=current), \
                patch.object(PORTAL.os, "geteuid", return_value=0, create=True):
            with self.assertRaises(RuntimeError):
                PORTAL.isolated(original, current)

    def test_non_root_mapping_cannot_impersonate_the_private_system_bus(self):
        with patch.object(PORTAL, "namespaces", return_value={name: name + ":[2]" for name in PORTAL.NAMESPACES}), \
                patch.object(PORTAL.os, "geteuid", return_value=1000, create=True):
            with self.assertRaises(RuntimeError):
                original = {name: name + ":[1]" for name in PORTAL.NAMESPACES}
                PORTAL.isolated(original, original)


if __name__ == "__main__":
    unittest.main()
