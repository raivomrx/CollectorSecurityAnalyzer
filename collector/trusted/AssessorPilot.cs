using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using CSA.Trust;

namespace CSA.Collector
{
    internal static partial class Program
    {
        internal static int InspectAssessorPilot(string[] args)
        {
            try
            {
                Protocol.Require(args.Length == 4 && args[2] == "--approval-sha256", "CSA-PILOT-ARGUMENTS");
                string bundle = Path.GetFullPath(args[1]);
                byte[] bytes = ReadTrustedInput(Path.Combine(bundle, "pilot-approval.json"), 4 * 1024 * 1024);
                Protocol.Artifact(bytes, args[3]);
                Dictionary<string, object> approval = Protocol.ReadCanonical(bytes);
                // This is the assessor-side inspector, not endpoint execution.
                BundleMetadata metadata = VerifyAssessorPilot(bundle, args[3],
                    ReadTrustedInput(Process.GetCurrentProcess().MainModule.FileName, 16 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "Start-CSATrustedCollector.ps1"), 1024 * 1024),
                    Protocol.Text(approval, "endpointBinding"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                Dictionary<string, object> policy = Protocol.Object(approval["policy"]);
                Dictionary<string, object> facts = InspectAuthenticatedBundle(bundle, metadata, policy);
                facts["policyDigest"] = Protocol.Digest(Encoding.UTF8.GetBytes(Protocol.Canonical(policy)));
                facts["approvalDigest"] = Protocol.Digest(bytes);
                facts["approvalState"] = "ASSESSOR_VERIFIED_PILOT";
                facts["expiresAt"] = Math.Min(Protocol.Number(approval, "expiresAt"), Protocol.Number(metadata.Session, "expiresAt"));
                Console.WriteLine(Protocol.Canonical(new Dictionary<string, object> {
                    { "assurance", "ASSESSOR_VERIFIED_PILOT" }, { "facts", facts } }));
                return 0;
            }
            catch (TrustFailure error) { Console.Error.WriteLine(error.Message); return 1; }
            catch { Console.Error.WriteLine("CSA-PILOT-INSPECTION-FAILED"); return 1; }
        }

        internal static string PilotEndpointBinding()
        {
            using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false))
            {
                string value = key == null ? "" : Convert.ToString(key.GetValue("MachineGuid"));
                Protocol.Require(!String.IsNullOrWhiteSpace(value), "CSA-PILOT-ENDPOINT");
                return Protocol.Digest(Encoding.UTF8.GetBytes(value.Trim().ToLowerInvariant()));
            }
        }

        internal static BundleMetadata VerifyAssessorPilot(string bundle, string expectedApproval, byte[] executable,
            byte[] entry, string endpoint, long now)
        {
            byte[] bytes = ReadTrustedInput(Path.Combine(bundle, "pilot-approval.json"), 4 * 1024 * 1024);
            Protocol.Artifact(bytes, expectedApproval);
            Dictionary<string, object> approval = Protocol.ReadCanonical(bytes);
            Protocol.Fields(approval, "objectType", "schemaVersion", "issuedAt", "expiresAt", "assurance",
                "approvedBy", "customerApprovalReference", "assessorApprovalReference", "independentChannelReference",
                "endpointBinding", "policy", "publisherManifestDigest", "sessionEnvelopeDigest", "packageDigest",
                "publisherSignatureDigest", "sessionSignatureDigest", "approvedAt", "sourceAddress");
            Protocol.Require(Protocol.Text(approval, "objectType") == "CSA_ASSESSOR_PILOT"
                && Protocol.Number(approval, "schemaVersion") == 1
                && Protocol.Text(approval, "assurance") == "ASSESSOR_VERIFIED_PILOT", "CSA-PILOT-APPROVAL");
            Protocol.Window(approval, now);
            System.Net.IPAddress sourceAddress;
            Protocol.Require(Protocol.Number(approval, "approvedAt") > 0 && Protocol.Number(approval, "approvedAt") <= now + 120
                && System.Net.IPAddress.TryParse(Protocol.Text(approval, "sourceAddress"), out sourceAddress), "CSA-PILOT-APPROVAL");
            Protocol.Require(Protocol.Number(approval, "expiresAt") - Protocol.Number(approval, "issuedAt") <= 28800,
                "CSA-PILOT-EXPIRED");
            foreach (string field in new[] { "approvedBy", "customerApprovalReference", "assessorApprovalReference", "independentChannelReference" })
                Protocol.Require(!String.IsNullOrWhiteSpace(Protocol.Text(approval, field))
                    && Protocol.Text(approval, field).Length <= 160, "CSA-PILOT-APPROVAL");
            Protocol.Require(endpoint == Protocol.Text(approval, "endpointBinding"), "CSA-PILOT-ENDPOINT");
            Dictionary<string, object> policy = Protocol.Policy(Encoding.UTF8.GetBytes(Protocol.Canonical(Protocol.Object(approval["policy"]))), now);
            BundleMetadata metadata = BundleMetadata.Verify(policy,
                ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.json"), 2 * 1024 * 1024),
                ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.p7s"), 65536),
                ReadTrustedInput(Path.Combine(bundle, "session-envelope.json"), 1024 * 1024),
                ReadTrustedInput(Path.Combine(bundle, "session-envelope.p7s"), 65536), executable, entry, now);
            Protocol.Require(Protocol.Number(metadata.Session, "schemaVersion") == 1, "CSA-PILOT-SESSION");
            foreach (string field in new[] { "publisherManifestDigest", "packageDigest" })
                Protocol.Require(Protocol.Text(approval, field) == Protocol.Text(metadata.Session, field), "CSA-PILOT-SESSION");
            Protocol.Require(Protocol.Text(approval, "sessionEnvelopeDigest") == Protocol.Digest(metadata.SessionBytes)
                && Protocol.Text(approval, "publisherSignatureDigest") == Protocol.Digest(metadata.PublisherSignature)
                && Protocol.Text(approval, "sessionSignatureDigest") == Protocol.Digest(metadata.SessionSignature)
                && Protocol.Number(approval, "expiresAt") <= Protocol.Number(metadata.Session, "expiresAt"), "CSA-PILOT-SESSION");
            byte[] package = ReadTrustedInput(Path.Combine(bundle, "collector.zip"), 64 * 1024 * 1024);
            Protocol.VerifyArchive(package, metadata.Release, metadata.Session);
            return metadata;
        }

        internal static int RunAssessorPilot(string[] args)
        {
            string bundle = null, approvalDigest = null, offline = null, root = null;
            bool quick = false;
            List<FileStream> leases = new List<FileStream>();
            int code = 1;
            try
            {
                HashSet<string> seen = new HashSet<string>();
                for (int i = 1; i < args.Length; i++)
                {
                    string name = args[i];
                    Protocol.Require(seen.Add(name), "CSA-PILOT-ARGUMENTS");
                    if (name == "--quick-run") { quick = true; continue; }
                    Protocol.Require(i + 1 < args.Length, "CSA-PILOT-ARGUMENTS");
                    string value = args[++i];
                    if (name == "--bundle") bundle = Path.GetFullPath(value);
                    else if (name == "--approval-sha256") approvalDigest = value;
                    else if (name == "--offline") offline = Path.GetFullPath(value);
                    else throw new TrustFailure("CSA-PILOT-ARGUMENTS");
                }
                Protocol.Require(bundle != null && approvalDigest != null, "CSA-PILOT-INDEPENDENT-HASH-REQUIRED");
                try { RejectElevatedProcess(); }
                catch (InvalidOperationException) { throw new TrustFailure("CSA-PILOT-STANDARD-USER-REQUIRED"); }
                RejectEnforcedScriptPolicy();
                Console.WriteLine("CSA phase: VERIFY / ASSESSOR_VERIFIED_PILOT");
                // Hold every supplied byte against replacement during verification and execution.
                foreach (string name in new[] { "pilot-approval.json", "publisher-manifest.json", "publisher-manifest.p7s",
                    "session-envelope.json", "session-envelope.p7s", "collector.zip", "Start-CSATrustedCollector.ps1" })
                {
                    string path = Path.Combine(bundle, name);
                    Protocol.Require((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, "CSA-PILOT-PATH");
                    leases.Add(RetryFileOperation(() => new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)));
                }
                string self = Process.GetCurrentProcess().MainModule.FileName;
                leases.Add(new FileStream(self, FileMode.Open, FileAccess.Read, FileShare.Read));
                BundleMetadata metadata = VerifyAssessorPilot(bundle, approvalDigest, ReadTrustedInput(self, 16 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "Start-CSATrustedCollector.ps1"), 1024 * 1024),
                    PilotEndpointBinding(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                byte[] package = ReadTrustedInput(Path.Combine(bundle, "collector.zip"), 64 * 1024 * 1024);
                Protocol.VerifyArchive(package, metadata.Release, metadata.Session);
                root = CreateRestrictedTemporaryDirectory();
                ExtractVerifiedArchive(package, root);
                VerifyTrustedConfiguration(root, metadata.Session);
                LeaseVerifiedFiles(package, root, leases);
                VerifyAssessorPilot(bundle, approvalDigest, ReadTrustedInput(self, 16 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "Start-CSATrustedCollector.ps1"), 1024 * 1024),
                    PilotEndpointBinding(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                Protocol.Window(metadata.Session, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                ConsumeEnvelope(metadata.Session);
                Console.WriteLine("Assurance: ASSESSOR_VERIFIED_PILOT / production Authenticode NOT_ESTABLISHED");
                Console.WriteLine("Privilege: STANDARD_USER / no elevation; engine and privacy profile verified.");
                Console.WriteLine("Execution transport: " + (quick ? "QUICK_RUN_PROCESS_BYPASS" : "STANDARD_POLICY"));
                PrintAssessmentSummary(root);
                Console.WriteLine("CSA phase: COLLECT / SUBMIT / signed receipt verification");
                code = RunPowerShell(root, offline != null, offline, true, quick);
                if (code != 0) Console.Error.WriteLine("CSA-PILOT-RUN-FAILED: retain the Windows control or submission diagnostic; request a new invitation.");
            }
            catch (TrustFailure error) { Console.Error.WriteLine(error.Message + ": Stop and contact the assessor using the independent handoff channel."); }
            catch (TransientFileLockException) { Console.Error.WriteLine("CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Request a fresh attempt."); }
            catch { Console.Error.WriteLine("CSA-PILOT-FAILED: Verification or collection stopped safely."); }
            finally
            {
                foreach (FileStream lease in leases) lease.Dispose();
                if (root != null && !RemoveTemporaryDirectory(root)) { code = 1; Console.Error.WriteLine("CSA-BOOT-CLEANUP"); }
                if (code == 0 && bundle != null)
                {
                    try
                    {
                        foreach (string name in new[] { "collector.zip", "session-envelope.json", "session-envelope.p7s" })
                            RetryFileOperation(() => { File.Delete(Path.Combine(bundle, name)); return true; });
                        Console.WriteLine("CSA phase: CLEANUP / temporary engine and private session files removed.");
                    }
                    catch { code = 1; Console.Error.WriteLine("CSA-BOOT-CLEANUP: Remove private handoff session files with the assessor."); }
                }
                else Console.WriteLine("CSA phase: CLEANUP / review and remove private handoff with the assessor.");
            }
            return code;
        }
    }
}
