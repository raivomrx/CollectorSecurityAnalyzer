"""Windows regression for production package verification and transient locks."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from csa_lab.collector_executable import build_bound_collector

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "nt", "Windows sharing violations require Windows")
class CollectorBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.harness = Path(cls.build.name) / "harness.exe"
        compiler = Path(os.environ["SystemRoot"]) / "Microsoft.NET/Framework64/v4.0.30319/csc.exe"
        result = subprocess.run([
            str(compiler), "/nologo", "/target:exe", "/main:BootstrapHarness",
            f"/out:{cls.harness}", "/reference:System.IO.Compression.dll",
            "/reference:System.IO.Compression.FileSystem.dll", "/reference:System.Web.Extensions.dll",
            str(ROOT / "collector/bootstrapper/Program.cs"),
            str(ROOT / "tests/fixtures/collector_bootstrap_harness.cs"),
        ], capture_output=True, text=True)
        if result.returncode:
            cls.build.cleanup()
            raise AssertionError(result.stdout + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # Hosted Windows runners can expose TEMP through an 8.3 alias. Match
        # the canonical script root used by the production PowerShell runner.
        self.root = Path(self.temporary.name).resolve()
        self.package = self.root / "package"
        self.package.mkdir()
        self.module = self.package / "collector/modules/Test.psm1"
        self.module.parent.mkdir(parents=True)
        self.module.write_bytes(b"# trusted Collector module\n")
        self.manifest = {"schemaVersion": "5.0", "files": [{
            "path": "collector/modules/Test.psm1", "size": self.module.stat().st_size,
            "sha256": "sha256:" + hashlib.sha256(self.module.read_bytes()).hexdigest(),
        }]}
        self.write_manifest()

    def write_manifest(self):
        (self.package / "trusted-manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def extract(self):
        bound = build_bound_collector(self.harness, self.package, self.root / "bound.exe")
        target = self.root / "extracted"
        target.mkdir(exist_ok=True)
        return subprocess.run([str(self.harness), "extract", str(bound), str(target)],
                              capture_output=True, text=True, timeout=20)

    def hold_module(self, seconds, path=None, wait=True):
        ready = self.root / "lock-ready"
        process = subprocess.Popen([sys.executable, str(ROOT / "tests/fixtures/hold_collector_file.py"),
                                    str(path or self.module), str(ready), str(seconds)])
        def close():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        self.addCleanup(close)
        deadline = time.monotonic() + 10
        while not ready.with_suffix(".watching").exists() and time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "Lock helper exited before watching the file")
            time.sleep(0.01)
        self.assertTrue(ready.with_suffix(".watching").exists())
        if not wait:
            return process
        while not ready.exists() and time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "Lock helper exited before acquiring the file")
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "Another process must hold the module before verification")
        return process

    def test_extraction_does_not_reopen_a_new_module_locked_by_another_process(self):
        # A trailing entry keeps extraction active after the newly created
        # module is exclusively opened by the independently running scanner.
        padding = self.package / "zz-padding.bin"
        padding.write_bytes(bytes(64 * 1024 * 1024))
        self.manifest["files"].append({"path": padding.name, "size": padding.stat().st_size,
                                      "sha256": "sha256:" + hashlib.sha256(padding.read_bytes()).hexdigest()})
        self.write_manifest()
        bound = build_bound_collector(self.harness, self.package, self.root / "bound.exe")
        target = self.root / "extracted"
        target.mkdir()
        module = target / "collector/modules/Test.psm1"
        process = self.hold_module(3, path=module, wait=False)
        result = subprocess.run([str(self.harness), "extract", str(bound), str(target)],
                                capture_output=True, text=True, timeout=20)
        completed = time.monotonic()
        self.assertEqual(result.returncode, 0, result.stderr)
        ready = self.root / "lock-ready"
        self.assertTrue(ready.exists(), "Scanner must acquire the module during extraction")
        self.assertLess(float(ready.read_text()), completed)
        self.assertIsNone(process.poll(), "Verification must finish while the module remains locked")
        with self.assertRaises(OSError):
            module.read_bytes()

    def powershell_hash(self, verify=False):
        # Load function definitions through the AST, without running collection.
        script = self.root / "hash.ps1"
        script.write_text("""param($Runner, $Module, $Mode)
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Runner, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw $errors[0] }
foreach ($node in $ast.EndBlock.Statements) {
    if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        . ([scriptblock]::Create($node.Extent.Text))
    }
}
$packageRoot = [System.IO.Path]::GetFullPath((Split-Path (Split-Path (Split-Path $Module -Parent) -Parent) -Parent))
try {
    if ($Mode -eq 'verify') { Test-CSATrustedPackage } else { Get-CSASha256File $Module }
} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
""", encoding="utf-8")
        return subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                               str(script), str(ROOT / "collector/windows/Invoke-CSACollector.ps1"), str(self.module),
                               "verify" if verify else "hash"],
                              capture_output=True, text=True, timeout=20)

    def test_stream_extraction_verifies_entry_digest_and_size(self):
        self.assertEqual(self.extract().returncode, 0)
        # Rebind the outer archive digest, retaining an incorrect trusted entry digest.
        self.module.write_bytes(b"# altered Collector module\n")
        result = self.extract_into_new_target()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("verification failed", result.stderr)
        self.assertNotIn("TRANSIENT_FILE_LOCK", result.stdout)

    def extract_into_new_target(self):
        bound = build_bound_collector(self.harness, self.package, self.root / "bound.exe")
        target = self.root / ("target-" + str(time.monotonic_ns()))
        target.mkdir()
        return subprocess.run([str(self.harness), "extract", str(bound), str(target)],
                              capture_output=True, text=True, timeout=20)

    def test_trust_failures_are_immediate_without_lock_retries(self):
        for mutation in ("digest", "size", "duplicate", "unsafe", "malformed", "missing", "undeclared"):
            with self.subTest(mutation=mutation):
                self.setUp()
                entry = self.manifest["files"][0]
                if mutation == "digest": entry["sha256"] = "not-a-digest"
                elif mutation == "size": entry["size"] += 1
                elif mutation == "duplicate": self.manifest["files"].append(dict(entry))
                elif mutation == "unsafe": entry["path"] = "collector/../escape.psm1"
                elif mutation == "malformed": self.manifest["files"] = {}
                elif mutation == "missing": self.manifest["files"].append({**entry, "path": "missing.psm1"})
                elif mutation == "undeclared": (self.package / "extra.psm1").write_text("extra")
                self.write_manifest()
                started = time.monotonic()
                result = self.extract_into_new_target()
                self.assertNotEqual(result.returncode, 0)
                self.assertLess(time.monotonic() - started, 3)
                self.assertNotIn("TRANSIENT_FILE_LOCK", result.stdout)

    def test_windows_bootstrap_retry_recovers_after_module_lock(self):
        self.hold_module(3)
        started = time.monotonic()
        result = subprocess.run([str(self.harness), "read", str(self.module)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertGreater(time.monotonic() - started, 2)
        self.assertIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.assertIn("trusted Collector module", result.stdout)

    def test_windows_powershell_hash_recovers_after_module_lock(self):
        self.hold_module(3)
        result = self.powershell_hash()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.assertIn(self.manifest["files"][0]["sha256"], result.stdout)

    def test_powershell_rejects_malformed_manifest_before_touching_locked_module(self):
        self.manifest["files"][0]["sha256"] = "invalid-digest"
        self.write_manifest()
        self.hold_module(30)
        started = time.monotonic()
        result = self.powershell_hash(verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("file entry is invalid", result.stderr)
        self.assertNotIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.assertLess(time.monotonic() - started, 3)

    def test_powershell_verifies_package_and_rejects_digest_mismatch(self):
        self.hold_module(3)
        result = self.powershell_hash(verify=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.module.write_bytes(self.module.read_bytes().replace(b"trusted", b"altered"))
        started = time.monotonic()
        result = self.powershell_hash(verify=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest mismatch", result.stderr)
        self.assertNotIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.assertLess(time.monotonic() - started, 3)

    def test_windows_persistent_lock_fails_closed_in_both_transports(self):
        for mode in ("exe", "powershell"):
            with self.subTest(mode=mode):
                self.setUp()
                process = self.hold_module(30)
                started = time.monotonic()
                result = (self.powershell_hash() if mode == "powershell" else subprocess.run(
                    [str(self.harness), "read", str(self.module)], capture_output=True, text=True, timeout=20))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TRANSIENT_FILE_LOCK", result.stderr)
                self.assertLess(time.monotonic() - started, 16)
                process.terminate()
                process.wait(timeout=5)

    def test_other_io_errors_are_not_retried(self):
        started = time.monotonic()
        result = subprocess.run([str(self.harness), "read", str(self.root / "missing.psm1")],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("TRANSIENT_FILE_LOCK", result.stdout)
        self.assertLess(time.monotonic() - started, 3)
