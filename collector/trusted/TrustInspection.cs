using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using CSA.Trust;

namespace CSA.Collector
{
    internal static partial class Program
    {
        internal static int InspectTrustedBundle(string[] args)
        {
            try
            {
                Protocol.Require(args.Length == 6 && args[2] == "--policy" && args[4] == "--approval", "CSA-TRUST-ARGUMENTS");
                Protocol.ProtectedPath(args[3]);
                Protocol.ProtectedPath(args[5]);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                byte[] policyBytes = ReadTrustedInput(args[3], 4 * 1024 * 1024);
                byte[] approvalBytes = ReadTrustedInput(args[5], 1024 * 1024);
                Dictionary<string, object> policy = Protocol.Policy(policyBytes, now);
                string self = Process.GetCurrentProcess().MainModule.FileName;
                string installed = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "CSA", "Collector", "CSA-TrustedCollector.exe");
                Protocol.Require(String.Equals(self, installed, StringComparison.OrdinalIgnoreCase), "CSA-TRUST-INSTALLATION");
                Protocol.ProtectedPath(self);
                VerifyPublisherExecutable(self, policy, now);
                string entry = Path.Combine(Path.GetDirectoryName(self), "Start-CSATrustedCollector.ps1");
                Protocol.ProtectedPath(entry);
                Protocol.Require(Authenticode.Valid(entry), "CSA-TRUST-AUTHENTICODE");
                string bundle = Path.GetFullPath(args[1]);
                BundleMetadata metadata = BundleMetadata.Verify(policy,
                    ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.json"), 2 * 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "publisher-manifest.p7s"), 65536),
                    ReadTrustedInput(Path.Combine(bundle, "session-envelope.json"), 1024 * 1024),
                    ReadTrustedInput(Path.Combine(bundle, "session-envelope.p7s"), 65536),
                    ReadTrustedInput(self, 16 * 1024 * 1024), ReadTrustedInput(entry, 1024 * 1024), now);
                Dictionary<string, object> approval = Protocol.ReadCanonical(approvalBytes);
                VerifyDistributionApproval(approval, metadata, policy, now);
                Dictionary<string, object> facts = InspectAuthenticatedBundle(bundle, metadata, policy);
                facts["policyDigest"] = Protocol.Digest(policyBytes);
                facts["approvalDigest"] = Protocol.Digest(approvalBytes);
                facts["approvalState"] = Protocol.Text(approval, "state");
                facts["expiresAt"] = new[] { Protocol.Number(metadata.Session, "expiresAt"), Protocol.Number(policy, "revocationFreshUntil"),
                    Protocol.Number(approval, "expiresAt") }.Min();
                Console.WriteLine(Protocol.Canonical(new Dictionary<string, object> { { "assurance", "REAL" }, { "facts", facts } }));
                return 0;
            }
            catch (TrustFailure error) { Console.Error.WriteLine(error.Message); return 1; }
            catch { Console.Error.WriteLine("CSA-TRUST-INSPECTION-FAILED"); return 1; }
        }

        internal static Dictionary<string, object> InspectAuthenticatedBundle(string bundle, BundleMetadata metadata, Dictionary<string, object> policy)
        {
            byte[] package = ReadTrustedInput(Path.Combine(bundle, "collector.zip"), 64 * 1024 * 1024);
            Protocol.VerifyArchive(package, metadata.Release, metadata.Session);
            string root = CreateRestrictedTemporaryDirectory();
            List<FileStream> leases = new List<FileStream>();
            try
            {
                ExtractVerifiedArchive(package, root);
                VerifyTrustedConfiguration(root, metadata.Session);
                LeaseVerifiedFiles(package, root, leases);
                Dictionary<string, object> manifest = ReadJsonObject(new MemoryStream(ReadTrustedInput(Path.Combine(root, "trusted-manifest.json"), 4 * 1024 * 1024)));
                Dictionary<string, object> result = new Dictionary<string, object>();
                foreach (string field in new[] { "assessmentId", "sessionId", "envelopeId", "recipientId", "expiresAt", "labId",
                    "publisherManifestDigest", "packageDigest", "sessionManifestDigest", "profileDigest", "privacyPolicyDigest", "tlsFingerprint", "origin" })
                    result[field] = metadata.Session[field];
                result["collectorBuildDigest"] = Protocol.Text(manifest, "collectorBuildDigest");
                result["sessionEnvelopeDigest"] = Protocol.Digest(metadata.SessionBytes);
                result["publisherSignatureDigest"] = Protocol.Digest(metadata.PublisherSignature);
                result["sessionSignatureDigest"] = Protocol.Digest(metadata.SessionSignature);
                result["publisherKeyId"] = metadata.Release["keyId"];
                result["labKeyId"] = metadata.Session["keyId"];
                Dictionary<string, object> publisher = Protocol.Key(policy, "publishers", Protocol.Text(metadata.Release, "keyId"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                Dictionary<string, object> lab = Protocol.Key(policy, "labs", Protocol.Text(metadata.Session, "keyId"), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                result["publisherSpkiSha256"] = publisher["spkiSha256"];
                result["publisherCertificateSha256"] = publisher["certificateSha256"];
                result["labSpkiSha256"] = lab["spkiSha256"];
                return result;
            }
            finally
            {
                foreach (FileStream lease in leases) lease.Dispose();
                Protocol.Require(RemoveTemporaryDirectory(root), "CSA-BOOT-CLEANUP");
            }
        }

        internal static void VerifyDistributionApproval(Dictionary<string, object> approval, BundleMetadata metadata, Dictionary<string, object> policy, long now)
        {
            Protocol.Fields(approval, "objectType", "schemaVersion", "issuedAt", "expiresAt", "state", "publisherKeyId", "labKeyId",
                "recipientId", "origin", "tlsFingerprint", "publisherLegalEntity", "publisherKeyOwner", "publisherPinSource",
                "labKeyOwner", "labPinSource", "independentChannel", "channelOwner", "channelEvidenceDigest",
                "homeLabAcceptanceDigest", "publisherManifestDigest", "assessmentId", "sessionId");
            Protocol.Require(Protocol.Text(approval, "objectType") == "CSA_DISTRIBUTION_APPROVAL"
                && Protocol.Number(approval, "schemaVersion") == 1, "CSA-TRUST-ENROLLMENT");
            Protocol.Window(approval, now);
            Protocol.Require(Protocol.Number(approval, "expiresAt") <= Protocol.Number(policy, "expiresAt"), "CSA-TRUST-EXPIRED");
            string state = Protocol.Text(approval, "state");
            Protocol.Require(state == "PILOT_APPROVED" || state == "RELEASE_APPROVED", "TRUST_ENROLLMENT_PENDING");
            foreach (string field in new[] { "recipientId", "origin", "tlsFingerprint", "publisherManifestDigest", "assessmentId", "sessionId" })
                Protocol.Require(Protocol.Text(approval, field) == Protocol.Text(metadata.Session, field), "CSA-TRUST-ENROLLMENT");
            Protocol.Require(Protocol.Text(approval, "publisherKeyId") == Protocol.Text(metadata.Release, "keyId")
                && Protocol.Text(approval, "labKeyId") == Protocol.Text(metadata.Session, "keyId"), "CSA-TRUST-ENROLLMENT");
            Protocol.Require(new[] { "MANAGED_SOFTWARE", "ASSESSOR_VERIFIED_HANDOFF" }.Contains(Protocol.Text(approval, "independentChannel")), "TRUST_ENROLLMENT_PENDING");
            foreach (string field in new[] { "publisherLegalEntity", "publisherKeyOwner", "publisherPinSource", "labKeyOwner", "labPinSource", "channelOwner" })
            {
                string value = Protocol.Text(approval, field);
                Protocol.Require(!String.IsNullOrWhiteSpace(value) && !Regex.IsMatch(value, "PENDING|UNKNOWN|UNSELECTED|EXAMPLE|TEST_ONLY|PLACEHOLDER", RegexOptions.IgnoreCase), "TRUST_ENROLLMENT_PENDING");
            }
            foreach (string field in new[] { "channelEvidenceDigest", "homeLabAcceptanceDigest" })
                Protocol.Require(Regex.IsMatch(Protocol.Text(approval, field), "\\Asha256:[0-9a-f]{64}\\z"), "TRUST_ENROLLMENT_PENDING");
        }
    }
}
