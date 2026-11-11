using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CSA.Trust;

namespace CSA.Collector
{
    internal static class TrustedEntry
    {
        private static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--assessor-pilot") return Program.RunAssessorPilot(args);
            if (args.Length > 0 && args[0] == "--inspect-assessor-pilot") return Program.InspectAssessorPilot(args);
            if (args.Length > 0 && args[0] == "--inspect-bundle") return Program.InspectTrustedBundle(args);
            return Program.RunTrusted(args);
        }
    }

    internal static partial class Program
    {
        internal static int RunTrusted(string[] args)
        {
            string root = null;
            string downloaded = null;
            int exitCode = 1;
            List<FileStream> leases = new List<FileStream>();
            try
            {
                WriteHeading();
                TrustedOptions options = TrustedOptions.Parse(args);
                string policyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CSA", "Trust", "policy.json");
                Protocol.Require(File.Exists(policyPath), "TRUST_NOT_ESTABLISHED");
                RejectElevatedProcess();
                Protocol.ProtectedPath(policyPath);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Dictionary<string, object> policy = Protocol.Policy(ReadTrustedInput(policyPath, 4 * 1024 * 1024), now);
                string self = Process.GetCurrentProcess().MainModule.FileName;
                string installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CSA", "Collector", "CSA-TrustedCollector.exe");
                Protocol.Require(String.Equals(self, installed, StringComparison.OrdinalIgnoreCase), "CSA-TRUST-INSTALLATION");
                Protocol.ProtectedPath(self);
                VerifyPublisherExecutable(self, policy, now);
                RejectEnforcedScriptPolicy();
                // The bundle is data. Never execute a downloaded entry point.
                string bundle;
                if (options.LabId != null)
                {
                    NetworkBundle fetched = NetworkBootstrap.Acquire(policy, options.LabId, options.EnvelopeId,
                        ReadTrustedInput(self, 16 * 1024 * 1024),
                        ReadTrustedInput(Path.Combine(Path.GetDirectoryName(self), "Start-CSATrustedCollector.ps1"), 1024 * 1024),
                        ReadAssessorSecret, code => Console.WriteLine("CSA phase: " + code),
                        options.QuickRun ? "QUICK_RUN_PROCESS_BYPASS" : "STANDARD_POLICY");
                    downloaded = CreateRestrictedTemporaryDirectory();
                    foreach (KeyValuePair<string, byte[]> file in fetched.Files)
                        RetryFileOperation(() => { File.WriteAllBytes(ResolvePackagePath(downloaded, file.Key), file.Value); return true; });
                    bundle = downloaded;
                }
                else bundle = Path.GetFullPath(options.Bundle);
                BundleMetadata metadata = BundleMetadata.Verify(policy,
                    ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.json"), 4 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.p7s"), 65536),
                    ReadTrustedInput(Path.Combine(bundle, "session-envelope.json"), 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "session-envelope.p7s"), 65536),
                    ReadTrustedInput(self, 16 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(Path.GetDirectoryName(self), "Start-CSATrustedCollector.ps1"), 1024 * 1024), now);
                Dictionary<string, object> release = metadata.Release;
                Dictionary<string, object> session = metadata.Session;
                Protocol.Require(options.LabId != null || Protocol.Number(session, "schemaVersion") == 1,
                    "CSA-TRUST-AUTHORIZATION");

                byte[] package = ReadTrustedInput(Path.Combine(bundle, "collector.zip"), 64 * 1024 * 1024);
                Protocol.VerifyArchive(package, release, session);
                root = CreateRestrictedTemporaryDirectory();
                ExtractVerifiedArchive(package, root);
                VerifyTrustedConfiguration(root, session);
                // Check the exact leased bytes once more to close the gap between
                // extraction and execution, then retain these read leases until exit.
                LeaseVerifiedFiles(package, root, leases);
                Protocol.Window(session, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                ConsumeEnvelope(session);
                Console.WriteLine("CSA-TRUST-VERIFIED: Publisher, Lab, session and engine accepted.");
                Console.WriteLine("Collector release: " + Protocol.Text(release, "version") + " / commit " + Protocol.Text(release, "commit"));
                Console.WriteLine("Publisher key: " + Protocol.Text(release, "keyId") + " / Windows signature VALID");
                Console.WriteLine("Immutable EXE SHA-256: " + Protocol.Text(release, "bootstrapSha256"));
                Console.WriteLine("Target Lab: " + Protocol.Text(session, "labId") + " / " + Protocol.Text(session, "origin"));
                Console.WriteLine("Session expires (UTC): " + DateTimeOffset.FromUnixTimeSeconds(Protocol.Number(session, "expiresAt")).ToString("u"));
                PrintAssessmentSummary(root);
                Console.WriteLine("CSA execution transport: " + (options.QuickRun ? "QUICK_RUN_PROCESS_BYPASS" : "STANDARD_POLICY"));
                exitCode = RunPowerShell(root, options.OfflineExport != null,
                    options.OfflineExport != null ? Path.GetFullPath(options.OfflineExport) : null, true, options.QuickRun);
                if (exitCode != 0) Console.Error.WriteLine("CSA-COL-POLICY-OR-RUN: Collection stopped. Record the Windows policy/application-control message for the assessor; protections remain enforced.");
            }
            catch (TrustFailure error)
            {
                if (error.Message == "CSA-COL-ORGANIZATION-POLICY")
                    Console.Error.WriteLine(error.Message + ": Your organization's Group Policy blocks PowerShell scripts, including Quick Run. Contact the assessor for an approved transport.");
                else
                    Console.Error.WriteLine(error.Message + ": Verification stopped. Contact the assessor using the approved trust channel.");
            }
            catch (TransientFileLockException)
            {
                Console.Error.WriteLine("CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Retry shortly.");
            }
            catch (TransientTransportFailure)
            {
                Console.Error.WriteLine("CSA-NETWORK-INTERRUPTED: The authenticated download was interrupted. Request a fresh assessor handoff if authorization was consumed.");
            }
            catch
            {
                Console.Error.WriteLine("CSA-TRUST-FAILED: Collector stopped safely. Record the diagnostic code for the assessor.");
            }
            finally
            {
                foreach (FileStream lease in leases) lease.Dispose();
                if (root != null && !RemoveTemporaryDirectory(root))
                {
                    exitCode = 1;
                    Console.Error.WriteLine("CSA-BOOT-CLEANUP: Temporary data cleanup requires assessor review.");
                }
                if (downloaded != null && !RemoveTemporaryDirectory(downloaded))
                {
                    exitCode = 1;
                    Console.Error.WriteLine("CSA-BOOT-CLEANUP: Download cleanup requires assessor review.");
                }
            }
            return exitCode;
        }

        private static byte[] ReadTrustedInput(string path, int maximum)
        {
            Protocol.Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "CSA-TRUST-PATH");
            return RetryFileOperation(() => {
                using (FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                    return Protocol.ReadBounded(input, maximum);
            });
        }

        internal static void LeaseVerifiedFiles(byte[] package, string root, List<FileStream> leases)
        {
            using (MemoryStream memory = new MemoryStream(package, false))
            using (ZipArchive archive = new ZipArchive(memory, ZipArchiveMode.Read, false))
            foreach (ZipArchiveEntry entry in archive.Entries)
            {
                string path = ResolvePackagePath(root, entry.FullName);
                Protocol.Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "CSA-TRUST-PATH");
                byte[] expected;
                using (Stream source = entry.Open())
                using (SHA256 hash = SHA256.Create()) expected = hash.ComputeHash(source);
                FileStream lease = RetryFileOperation(() => {
                    FileStream input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                    try
                    {
                        Protocol.Require(input.Length == entry.Length, "CSA-TRUST-STAGED-DIGEST");
                        using (SHA256 hash = SHA256.Create())
                            Protocol.Require(hash.ComputeHash(input).SequenceEqual(expected), "CSA-TRUST-STAGED-DIGEST");
                        input.Position = 0;
                        return input;
                    }
                    catch { input.Dispose(); throw; }
                });
                leases.Add(lease);
            }
        }

        internal static void VerifyTrustedConfiguration(string root, Dictionary<string, object> session)
        {
            Dictionary<string, object> config = ReadJsonObject(new MemoryStream(ReadTrustedInput(Path.Combine(root, "session-config.json"), 4 * 1024 * 1024)));
            Dictionary<string, object> manifest = ReadJsonObject(new MemoryStream(ReadTrustedInput(Path.Combine(root, "trusted-manifest.json"), 4 * 1024 * 1024)));
            foreach (string name in new[] { "assessmentId", "sessionId" })
                Protocol.Require(Protocol.Text(config, name) == Protocol.Text(session, name)
                    && Protocol.Text(manifest, name) == Protocol.Text(session, name), "CSA-TRUST-SESSION");
            Protocol.Require(Protocol.Text(config, "serverUrl") == Protocol.Text(session, "origin")
                && Protocol.Text(config, "serverCertificateFingerprint") == Protocol.Text(session, "tlsFingerprint")
                && Protocol.Text(manifest, "serverCertificateFingerprint") == Protocol.Text(session, "tlsFingerprint")
                && Protocol.Text(config, "collectorMode") == Protocol.Text(session, "mode")
                && Protocol.Text(config, "collectionProfile") == Protocol.Text(session, "profileId")
                && Protocol.Text(config, "collectionProfileDigest") == Protocol.Text(session, "profileDigest")
                && Protocol.Text(manifest, "collectionProfileDigest") == Protocol.Text(session, "profileDigest"), "CSA-TRUST-SCOPE");
            string privateProof = Protocol.Text(config, "trustedEnvelopeNonce");
            Protocol.Require(Protocol.Text(config, "trustedEnvelopeId") == Protocol.Text(session, "envelopeId")
                && NetworkBootstrap.Locator(privateProof), "CSA-TRUST-NONCE");
            if (Protocol.Number(session, "schemaVersion") == 2)
                Protocol.Require(Protocol.Digest(Encoding.ASCII.GetBytes(privateProof)) ==
                    Protocol.Text(Protocol.Object(session["submissionPolicy"]), "authorizationDigest"), "CSA-TRUST-NONCE");
            else Protocol.Require(privateProof == Protocol.Text(session, "nonce"), "CSA-TRUST-NONCE");
            string privacy = Protocol.Text(config, "privacyPolicy");
            Protocol.SafePath(privacy);
            Protocol.Require(privacy.StartsWith("collector/profiles/", StringComparison.Ordinal)
                && privacy.EndsWith(".json", StringComparison.Ordinal), "CSA-TRUST-PRIVACY");
            Protocol.Require(Protocol.Digest(ReadTrustedInput(ResolvePackagePath(root, privacy), 1024 * 1024)) == Protocol.Text(session, "privacyPolicyDigest"),
                "CSA-TRUST-PRIVACY");
            DateTimeOffset expiry;
            Protocol.Require(DateTimeOffset.TryParse(Protocol.Text(config, "expiresAt"), out expiry)
                && expiry.ToUnixTimeSeconds() == Protocol.Number(session, "expiresAt"), "CSA-TRUST-EXPIRED");
            using (X509Certificate2 certificate = new X509Certificate2(ReadTrustedInput(Path.Combine(root, "server-cert.pem"), 65536)))
                Protocol.Require(Protocol.Digest(certificate.RawData) == Protocol.Text(session, "tlsFingerprint"), "CSA-TRUST-TLS");
        }

        private static void ConsumeEnvelope(Dictionary<string, object> session)
        {
            string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CSA", "Trust", "used");
            Directory.CreateDirectory(directory);
            string key = Protocol.Digest(Encoding.UTF8.GetBytes(Protocol.Text(session, "labId") + "\n" +
                Protocol.Text(session, "envelopeId") + "\n" + Protocol.Text(session, "nonce"))).Substring(7);
            try
            {
                using (FileStream marker = new FileStream(Path.Combine(directory, key), FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    marker.Flush(true);
            }
            catch (IOException) { throw new TrustFailure("CSA-TRUST-REPLAY"); }
        }

        private static void VerifyPublisherExecutable(string path, Dictionary<string, object> policy, long now)
        {
            Protocol.Require(Authenticode.Valid(path), "CSA-TRUST-AUTHENTICODE");
            using (X509Certificate2 certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path)))
            using (RSA rsa = certificate.GetRSAPublicKey())
            {
                string pin = Protocol.SpkiDigest(rsa);
                string digest = Protocol.Digest(certificate.RawData);
                Dictionary<string, object>[] keys = Protocol.Rows(policy, "publishers").Select(Protocol.Object)
                    .Where(item => Protocol.Text(item, "spkiSha256") == pin && Protocol.Text(item, "certificateSha256") == digest).ToArray();
                Protocol.Require(keys.Length == 1 && rsa.KeySize >= 3072, "CSA-TRUST-PUBLISHER");
                Protocol.Key(policy, "publishers", Protocol.Text(keys[0], "keyId"), now);
            }
        }

        private static string ReadAssessorSecret()
        {
            Protocol.Require(!Console.IsInputRedirected, "CSA-TRUST-SECURE-PROMPT");
            Console.Write("Enter the one-time authorization from the independent assessor handoff (input hidden): ");
            StringBuilder secret = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Escape) throw new TrustFailure("CSA-TRUST-CANCELLED");
                if (key.Key == ConsoleKey.Backspace) { if (secret.Length > 0) secret.Length--; continue; }
                Protocol.Require(secret.Length < 128 && (Char.IsLetterOrDigit(key.KeyChar) && key.KeyChar < 128
                    || key.KeyChar == '_' || key.KeyChar == '-'), "CSA-TRUST-AUTHORIZATION");
                secret.Append(key.KeyChar);
            }
            Console.WriteLine();
            return secret.ToString();
        }

        internal static void RejectEnforcedScriptPolicy()
        {
            using (Microsoft.Win32.RegistryKey machine = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Policies\Microsoft\Windows\PowerShell", false))
            using (Microsoft.Win32.RegistryKey user = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Policies\Microsoft\Windows\PowerShell", false))
            {
                VerifyEnforcedScriptPolicy(machine == null ? null : machine.GetValue("EnableScripts"),
                    machine == null ? null : machine.GetValue("ExecutionPolicy"), user == null ? null : user.GetValue("EnableScripts"),
                    user == null ? null : user.GetValue("ExecutionPolicy"));
            }
        }

        internal static void VerifyEnforcedScriptPolicy(object machineEnabled, object machinePolicy, object userEnabled, object userPolicy)
        {
            // Windows PowerShell evaluates MachinePolicy before UserPolicy.
            bool machineConfigured = machineEnabled != null || machinePolicy != null;
            object enabled = machineConfigured ? machineEnabled : userEnabled;
            object policy = machineConfigured ? machinePolicy : userPolicy;
            Protocol.Require(Convert.ToString(enabled) != "0"
                && !String.Equals(Convert.ToString(policy), "Restricted", StringComparison.OrdinalIgnoreCase),
                "CSA-COL-ORGANIZATION-POLICY");
        }
    }

    internal sealed class TrustedOptions
    {
        internal string Bundle, LabId, EnvelopeId, OfflineExport;
        internal bool QuickRun;
        internal static TrustedOptions Parse(string[] args)
        {
            TrustedOptions options = new TrustedOptions();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < args.Length; index++)
            {
                string flag = args[index];
                Protocol.Require(seen.Add(flag), "CSA-TRUST-ARGUMENTS");
                if (flag == "--quick-run") { options.QuickRun = true; continue; }
                Protocol.Require(index + 1 < args.Length, "CSA-TRUST-ARGUMENTS");
                string value = args[++index];
                if (flag == "--bundle") options.Bundle = value;
                else if (flag == "--lab") options.LabId = value;
                else if (flag == "--envelope") options.EnvelopeId = value;
                else if (flag == "--offline") options.OfflineExport = value;
                else throw new TrustFailure("CSA-TRUST-ARGUMENTS");
            }
            Protocol.Require(options.Bundle != null && options.LabId == null && options.EnvelopeId == null
                || options.Bundle == null && options.LabId != null && options.EnvelopeId != null, "CSA-TRUST-ARGUMENTS");
            return options;
        }
    }
}

namespace CSA.Trust
{
    internal static class Authenticode
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FileInfo { public uint size; public string path; public IntPtr file; public IntPtr subject; }
        [StructLayout(LayoutKind.Sequential)]
        private struct TrustData
        {
            public uint size; public IntPtr callback; public IntPtr sip; public uint ui; public uint revocation;
            public uint choice; public IntPtr file; public uint stateAction; public IntPtr state; public IntPtr url;
            public uint flags; public uint context;
        }
        [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
        private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);

        internal static bool Valid(string path)
        {
            FileInfo file = new FileInfo { size = (uint)Marshal.SizeOf(typeof(FileInfo)), path = path };
            IntPtr pointer = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(FileInfo)));
            try
            {
                Marshal.StructureToPtr(file, pointer, false);
                TrustData data = new TrustData { size = (uint)Marshal.SizeOf(typeof(TrustData)), ui = 2,
                    revocation = 1, choice = 1, file = pointer, flags = 0x80 };
                Guid action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
                return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0;
            }
            finally { Marshal.DestroyStructure(pointer, typeof(FileInfo)); Marshal.FreeCoTaskMem(pointer); }
        }
    }
}
