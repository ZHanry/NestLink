"""Check Git source candidates for obvious secrets without displaying values.

Include tracked and untracked nonignored files, using Git's NUL-delimited file
list rather than walking build caches. Gitleaks remains a separate CI check.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
_PEM_SPACE = r"(?:\s|\\[nr])"
_PEM_LINE = r"(?:\r\n|\r|\n|\\r\\n|\\n|\\r)"
PATTERNS = (
    re.compile(
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
        + _PEM_SPACE + r"*"
        + r"(?:(?:Proc-Type|DEK-Info):[A-Za-z0-9 ,:_=-]*" + _PEM_LINE + _PEM_SPACE + r"*)*"
        + r"(?P<body>(?:[A-Za-z0-9+/=]" + _PEM_SPACE + r"*){32,})"
    ),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)\b(?:password|secret|token)\b\s*[:=]\s*['\"][^'\"]{8,}"),
)
RULE_NAMES = (
    "private-key-body", "aws-access-key", "github-token",
    "github-fine-grained-token", "slack-token", "credential-assignment",
)

# Reviewed public test assignments only. Each digest covers the COMPLETE
# pattern-5 match, including field name, assignment punctuation and the literal.
# A new value, another path, or a match from any other rule is never exempt.
# Review rationale: docs/refactor/SECRET-SCAN-REVIEW-2026-10-17.md
# and docs/refactor/SECRET-SCAN-REVIEW-2026-11-06.md.
PUBLIC_TEST_ASSIGNMENT_SHA256 = {
    "crates/node/src/service_plane/ingress/web/tests.rs": frozenset((
        "e3940e3a2d6cb8bcd66cb6fab4d5561a076497ab1872afef512ee3d3ad7bda6a",
    )),
    "crates/sdk/src/webrtc_host/tests/data_loopback_tests.rs": frozenset((
        "acb74a6b9bf2e17de4d5b8c4d5cd31aebc17612d1d4a57c679895e69667f897d",
        "31181993db42e794802e1bb7052a89f037a9a776f5e00e0c2b04b506c1192aa7",
    )),
    "crates/sdk/tests/service_publication.rs": frozenset((
        "1700e3129a5b8e69b158ac4c1f520ff4ffe907dfec42d6e41638388eed9ab90a",
    )),
    "crates/sdk/tests/service_start_cancellation.rs": frozenset((
        "1700e3129a5b8e69b158ac4c1f520ff4ffe907dfec42d6e41638388eed9ab90a",
    )),
    "crates/sdk/tests/service_web_publication.rs": frozenset((
        "ef2d828e52c6c4ab691e7f50791930930ba7934cd361f100a54918da35fffcd3",
    )),
    "crates/storage/src/services/publication/tests.rs": frozenset((
        "3b9d9a3627c940323e07c7517ef32caebbc72693455cb44755840f62af726d92",
    )),
    "crates/turn-service/src/tests.rs": frozenset((
        "258ed9174893a1ab6b38daf019a7852c4e9a1d074ed532aac9a7a35904294f04",
        "4b43914e843b841114f82387396764f3c7da5889944745577d21e9c739c549ee",
        "abc32ee8b93aea9624c67be94104533d344544c59081b0e1377acf51c9e7494c",
        "b47551ee7ea0af0d4bbbb26b29aa9f30ad270a3ed04bdf3696d3af9ca801347f",
        "1c4da9e328a4d87a2380758088e6b8b977f1cfb828f25992f3cef61e4306071f",
        "1c14ebc64d2d0ecdc3e90def39d56feb5fc038ce3deae231fa18db26c017e5bc",
    )),
    "apps/server/src/remote_password.rs": frozenset((
        "f989e5d27d79aa152b22f90ea28e517f1e1b321c7acce575cad951c0aa5f6a14",
    )),
    "crates/storage/src/relay_reservations/tests/resources.rs": frozenset((
        "31bba86ff29bbf96f6c5826940280aea9cf2ef17ca7ea5807a06547d9caf6c46",
    )),
    "apps/daemon/src/diagnostics/export.rs": frozenset((
        "c854d8d51609d3cbc1d53c2e5ccc7a779f9cfdc5c5d0c0c80f2211361c21e987",
    )),
    "apps/daemon/src/private_service_proxy/host/tests.rs": frozenset((
        "607768c2d21021214db3711225d537311a71e885719d3199673f3bf84aee0d80",
    )),
    "apps/daemon/src/space_dns_system/tests.rs": frozenset((
        "ebe9d73f0ff772302508f6215a8c0d56e2a42062cc5b1f18aed8c3809555b286",
    )),
    "apps/server/src/node_control/revocation_tests.rs": frozenset((
        "907fca66db9b2b22bbe8cb581a8e3856b6db836ec4f3456e5d92422400cdc3b0",
    )),
    "apps/server/tests/internal_software_media_candidate.rs": frozenset((
        "7d748e29f38e96a0edf3b9a46cf6be5058227ca4bd2a367856247b5e291399ef",
    )),
    "crates/app-core/src/native_session.rs": frozenset((
        "2dd7f7052d66c7ad0e31d1ea899d0e1a756cead0fb602588300266158228e4bd",
    )),
    "crates/app-core/src/runtime/native_routed.rs": frozenset((
        "1c49017d6e6335e1ca8823979cb237b2ba5519ac0a06641424b9d2146252915d",
    )),
    "crates/protocol/src/native_ice.rs": frozenset((
        "6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444",
    )),
    "crates/sdk/tests/ice_relay_contract.rs": frozenset((
        "f11e4556d083551449a5e8b90afd81caa6fcc1e3d6729d3f6711eee4385f8fe3",
    )),
    "crates/sdk/tests/network_relay.rs": frozenset((
        "94a95b076f4e35c077355c092130454315ab7ecef7281f2fcd10f3f953f6fb72",
    )),
    "crates/storage/src/media_authority_tests.rs": frozenset((
        "757c3f0bab9545249f71a14b36608edf54b4dd1f8099e382739dfb12f2675f83",
        "a7fb0c0bbf493482fea1a69e807a52b2dec2f0cc17806ec1870e339027417293",
    )),
    "crates/storage/src/services/publication/tests/private_policy/offline.rs": frozenset((
        "c97cfd8a7f5d05d965234d0131f3ec3ad225924788039d1f761c509e9f08a688",
    )),
    "crates/storage/src/services/publication/tests/space_policy.rs": frozenset((
        "845b47bef3d6e8cb9c8dcdd305101b9a89e3369f911847d41a3c631c7aae7a82",
    )),
    "crates/storage/tests/control/native_ice_capabilities.rs": frozenset((
        "6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444",
    )),
    "crates/storage/tests/control/native_readiness.rs": frozenset((
        "6c1c869501c113082d5a0b724e2955c6ee446836f848df1bc06b6ead0527f444",
    )),
    "tests/refactor/test_browser_native_runner.py": frozenset((
        "c0dc8f1be2b46b0ef1fac85cf6b3b04bf41177820d0008bdfe2fe682d8c00d5e",
        "d2a786e79cf2b9f688a4964ddf294991d2bccd2704eb71cfff0d9923401844f1",
    )),
}


def has_pem_body(match):
    """Ignore markers and short invalid parser fixtures without key material.

    Accept normal/escaped newlines, line wrapping and traditional encrypted PEM
    headers. A decodable payload of 24 bytes also catches truncated key bodies;
    it need not have a closing marker or pass cryptographic key validation.
    """
    encoded = re.sub(_PEM_SPACE, "", match.group("body"))
    try:
        return len(base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)) >= 24
    except (ValueError, binascii.Error):
        return False


def scan_text(relative, text):
    findings = []
    for index, pattern in enumerate(PATTERNS):
        for match in pattern.finditer(text):
            if index == 0 and not has_pem_body(match):
                continue
            if index == 5 and hashlib.sha256(match.group().encode("utf-8")).hexdigest() in PUBLIC_TEST_ASSIGNMENT_SHA256.get(relative, ()):
                continue
            findings.append((relative, text.count("\n", 0, match.start()) + 1, RULE_NAMES[index]))
    return findings


def source_paths(root):
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
    )
    names = dict.fromkeys(os.fsdecode(item) for item in result.stdout.split(b"\0") if item)
    for name in names:
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("Git returned an unsafe source path")
        yield relative.as_posix()


def scan_sources(root):
    root = root.resolve()
    findings = []
    for relative in source_paths(root):
        path = root / relative
        if path.is_symlink():
            text = os.readlink(path)
        else:
            if not path.resolve().is_relative_to(root):
                raise ValueError("Git source resolves outside the repository")
            if not path.is_file():  # A tracked file may have been deleted locally.
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
        findings.extend(scan_text(relative, text))
    return findings


def main():
    try:
        findings = scan_sources(ROOT)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Secret scan could not read the Git source candidates.", file=sys.stderr)
        return 2
    if findings:
        print("Secret scan failed:\n" + "\n".join(
            f"{path}:{line}: {rule}" for path, line, rule in findings
        ), file=sys.stderr)
        return 1
    print("No obvious secrets in Git source text. CI still runs Gitleaks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
