"""Prevent retired clients from re-entering active CI and release boundaries."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


def module(name):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(result)
    return result


class ProductScopeTests(unittest.TestCase):
    def test_client_scope_and_backend_are_distinct(self):
        scope = json.loads((ROOT / "config/product-scope.json").read_text(encoding="utf-8"))
        self.assertEqual(scope["product"], "NestLink")
        self.assertEqual(scope["positioning"], ["内网穿透", "远程桌面"])
        self.assertEqual(set(scope["clients"]), {"windows", "web"})
        self.assertEqual(scope["backend"]["linux"]["architectures"], ["x86_64", "aarch64"])
        self.assertEqual(scope["distribution_builds"], "github-actions")
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
        self.assertNotIn("crates/android-bridge", workspace["members"])
        self.assertTrue({"apps/desktop", "apps/web", "apps/server"} <= set(workspace["members"]))
        self.assertFalse((ROOT / "apps/android/app/build.gradle.kts").exists())
        self.assertFalse((ROOT / ".github/workflows/android.yml").exists())

    def test_release_and_candidate_require_every_backend_without_retired_clients(self):
        candidate = module("refactor-candidate-producer")
        release = module("refactor-release-producer")
        publisher = module("refactor-rc-publish")
        self.assertEqual(set(candidate.EXPECTED),
                         {"windows-x64", "linux-x64", "linux-arm64", "web", "metadata", "oci-x64", "oci-arm64"})
        self.assertEqual(candidate.EXPECTED["linux-x64"], {"linux-x64-server", "linux-x64-network"})
        self.assertEqual(candidate.EXPECTED["linux-arm64"], {"linux-arm64-server", "linux-arm64-network"})
        self.assertEqual(candidate.NATIVE["linux-x64"][2], ("server", "daemon"))
        self.assertEqual(candidate.NATIVE["linux-arm64"][2], ("server", "daemon"))
        self.assertEqual(release.NATIVE["linux-x64"][2], ("server",))
        self.assertEqual(release.NATIVE["linux-arm64"][2], ("server",))
        self.assertEqual(candidate.CURRENT_ROLES, publisher.CURRENT_ROLES)
        self.assertEqual(candidate.REQUIRED_CASES, publisher.REQUIRED_CASES)
        for collection in (candidate.CURRENT_ROLES, candidate.REQUIRED_CASES,
                           release.FINAL_ROLES, release.PARTS, release.SECRETS):
            self.assertFalse(any("android" in item or ("linux" in item and "desktop" in item)
                                 for item in collection))
        self.assertTrue({"windows-10-installed", "windows-11-installed", "windows-privileged-input",
                         "linux-x64-server-installed", "linux-arm64-server-installed",
                         "chrome-current", "edge-current", "firefox-current", "company-to-home",
                         "turn-capacity-and-revoke", "install-upgrade-rollback-uninstall"}
                        <= candidate.REQUIRED_CASES)
        self.assertTrue({"original-edge-100", "native-1080p60", "input-display-ab",
                         "cross-day-24h-soak", "revocation-and-exit"} <= publisher.REMEDIATION_CASES)
        for parser in (candidate.parser(), release.parser()):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(["collect-android"])

    def test_linux_packager_refuses_new_desktop_before_reading_payload(self):
        builder = module("refactor-native-packaging")
        for role in ("desktop", "daemon", "privileged"):
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "backend servers only"):
                builder.executable_items({}, "linux", "x86_64", role)
        server = {"platform": "linux", "architecture": "aarch64", "format": "executable",
                  "role": "server", "path": "linux-aarch64/nestlink-server",
                  "state_compatibility": "v15-control-schema24-epoch1"}
        self.assertEqual(builder.executable_items({"artifacts": [server]}, "linux", "aarch64", "server"),
                         [server])

    def test_compiler_and_signing_policies_reject_retired_target(self):
        codecs = module("refactor-native-codecs")
        self.assertEqual(set(codecs.load_lock(codecs.DEFAULT_LOCK)["targets"]),
                         {"x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"})
        for target in ("aarch64-linux-android", "x86_64-linux-android"):
            with self.subTest(target=target), self.assertRaises(codecs.SupplyError):
                codecs.verify_build_host(target, "x86_64", "Linux", "posix")
        signing = json.loads((ROOT / "config/release-signatures.template.json").read_text(encoding="utf-8"))
        self.assertEqual(set(signing["identities"]), {"windows_certificate_sha256"})
        self.assertEqual({item["platform"] for item in signing["artifacts"]}, {"windows"})
        checks = module("refactor-required-checks")
        self.assertEqual(set(checks.WORKFLOWS),
                         {"rust-core.yml", "web-build.yml", "secret-scan.yml", "codeql.yml",
                          "network-rewrite.yml", "linux-network-package.yml", "network-upgrade.yml"})


if __name__ == "__main__":
    unittest.main()
