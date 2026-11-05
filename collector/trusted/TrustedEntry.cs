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
        private static int Main(string[] args) { return Program.RunTrusted(args); }
    }

    internal static partial class Program
    {
        internal static int RunTrusted(string[] args)
        {
            string root = null;
            int exitCode = 1;
            List<FileStream> leases = new List<FileStream>();
            try
            {
                WriteHeading();
                Protocol.Require((args.Length == 2 || args.Length == 4 && args[2] == "--offline") && args[0] == "--bundle", "CSA-TRUST-ARGUMENTS");
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
                // The bundle is data. Never execute a downloaded entry point.
                string bundle = Path.GetFullPath(args[1]);
                byte[] publisherBytes = ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.json"), 4 * 1024 * 1024);
                Dictionary<string, object> release = Protocol.VerifySigned(publisherBytes,
                    ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.p7s"), 65536), policy, "publishers", now);
                Protocol.Fields(release, "objectType", "schemaVersion", "keyId", "issuedAt", "expiresAt",
                    "releaseSequence", "version", "commit", "bootstrapSha256", "bootstrapSize", "entryPointSha256", "entryPointSize", "files", "profiles");
                Protocol.Require(Protocol.Text(release, "objectType") == "CSA_PUBLISHER_RELEASE" && Protocol.Number(release, "schemaVersion") == 1,
                    "CSA-TRUST-SCHEMA");
                Protocol.Require(Protocol.Number(release, "releaseSequence") >= Protocol.Number(policy, "minimumReleaseSequence"), "CSA-TRUST-ROLLBACK");
                byte[] executable = ReadTrustedInput(self, 16 * 1024 * 1024);
                byte[] entryPoint = ReadTrustedInput(Path.Combine(Path.GetDirectoryName(self), "Start-CSATrustedCollector.ps1"), 1024 * 1024);
                Protocol.Require(executable.LongLength == Protocol.Number(release, "bootstrapSize")
                    && entryPoint.LongLength == Protocol.Number(release, "entryPointSize"), "CSA-TRUST-BOOTSTRAP");
                Protocol.Artifact(executable, Protocol.Text(release, "bootstrapSha256"));
                Protocol.Artifact(entryPoint, Protocol.Text(release, "entryPointSha256"));

                byte[] sessionBytes = ReadTrustedInput(Path.Combine(bundle, "session-envelope.json"), 1024 * 1024);
                Dictionary<string, object> session = Protocol.VerifySigned(sessionBytes,
                    ReadTrustedInput(Path.Combine(bundle, "session-envelope.p7s"), 65536), policy, "labs", now);
                Protocol.Fields(session, "objectType", "schemaVersion", "keyId", "issuedAt", "expiresAt", "envelopeId",
                    "labId", "recipientId", "assessmentId", "sessionId", "origin", "tlsFingerprint", "mode",
                    "profileId", "profileDigest", "privacyPolicyDigest", "publisherManifestDigest",
                    "packageDigest", "sessionManifestDigest", "nonce", "submissionPolicy");
                Protocol.Require(Protocol.Text(session, "objectType") == "CSA_LAB_SESSION" && Protocol.Number(session, "schemaVersion") == 1,
                    "CSA-TRUST-SCHEMA");
                Dictionary<string, object> lab = Protocol.Key(policy, "labs", Protocol.Text(session, "keyId"), now);
                foreach (string field in new[] { "labId", "origin", "tlsFingerprint" })
                    Protocol.Require(Protocol.Text(lab, field) == Protocol.Text(session, field), "CSA-TRUST-LAB");
                Protocol.Origin(Protocol.Text(session, "origin"));
                Protocol.Require(System.Text.RegularExpressions.Regex.IsMatch(Protocol.Text(session, "envelopeId"), "\\A[A-Za-z0-9_-]{16,128}\\z")
                    && System.Text.RegularExpressions.Regex.IsMatch(Protocol.Text(session, "nonce"), "\\A[A-Za-z0-9_-]{16,128}\\z"), "CSA-TRUST-NONCE");
                Protocol.Require(Protocol.Text(policy, "endpointId") == Protocol.Text(session, "recipientId"), "CSA-TRUST-RECIPIENT");
                Protocol.Require(Protocol.Digest(publisherBytes) == Protocol.Text(session, "publisherManifestDigest"), "CSA-TRUST-SESSION");
                Protocol.Require(Protocol.Text(session, "mode") == "STANDARD_USER_COLLECTION", "CSA-TRUST-MODE");
                Protocol.Require(Protocol.Number(session, "expiresAt") - Protocol.Number(session, "issuedAt") <= 86400, "CSA-TRUST-EXPIRED");
                Dictionary<string, object> submission = Protocol.Object(session["submissionPolicy"]);
                Protocol.Fields(submission, "transport", "maximumBytes", "receiptRequired");
                Protocol.Require(Protocol.Text(submission, "transport") == "HTTPS_OR_ENCRYPTED_OFFLINE"
                    && Protocol.Number(submission, "maximumBytes") > 0 && Protocol.Number(submission, "maximumBytes") <= 128 * 1024 * 1024
                    && submission["receiptRequired"] is bool && (bool)submission["receiptRequired"], "CSA-TRUST-SCOPE");

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
                exitCode = RunPowerShell(root, args.Length == 4, args.Length == 4 ? Path.GetFullPath(args[3]) : null, true);
            }
            catch (TrustFailure error)
            {
                Console.Error.WriteLine(error.Message + ": Verification stopped. Contact the assessor using the approved trust channel.");
            }
            catch (TransientFileLockException)
            {
                Console.Error.WriteLine("CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Retry shortly.");
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
            Protocol.Require(Protocol.Text(config, "trustedEnvelopeId") == Protocol.Text(session, "envelopeId")
                && Protocol.Text(config, "trustedEnvelopeNonce") == Protocol.Text(session, "nonce"), "CSA-TRUST-NONCE");
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
