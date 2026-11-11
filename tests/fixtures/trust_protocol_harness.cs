using System;
using System.Collections.Generic;
using System.IO;
using System.Web.Script.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CSA.Trust;

internal static class TrustHarness
{
    private static int Main(string[] args)
    {
        JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
        if (args[0] == "--self-sign")
        {
            // Test-only identity stays in memory; no store/root enrollment.
            byte[] bytes = Encoding.UTF8.GetBytes(Console.In.ReadToEnd());
            using (RSA rsa = new RSACng(3072))
            {
                CertificateRequest request = new CertificateRequest("CN=CSA ephemeral CMS fixture", rsa,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1)))
                {
                    SignedCms cms = new SignedCms(new ContentInfo(bytes), true);
                    CmsSigner signer = new CmsSigner(certificate) { IncludeOption = X509IncludeOption.EndCertOnly };
                    signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");
                    cms.ComputeSignature(signer, true);
                    Console.WriteLine(json.Serialize(new Dictionary<string, object> {
                        { "signature", Convert.ToBase64String(cms.Encode()) },
                        { "keySize", rsa.KeySize }, { "spkiSha256", Protocol.SpkiDigest(rsa) },
                        { "certificateSha256", Protocol.Digest(certificate.RawData) } }));
                }
            }
            return 0;
        }
        object[] cases = (object[])json.DeserializeObject(File.ReadAllText(args[0]));
        List<object> outcomes = new List<object>();
        foreach (object item in cases)
        {
            Dictionary<string, object> row = (Dictionary<string, object>)item;
            try
            {
                long now = Convert.ToInt64(row["now"]);
                string kind = (string)row["kind"];
                if (kind == "pilot")
                {
                    string bundle = (string)row["root"];
                    BundleMetadata metadata = CSA.Collector.Program.VerifyAssessorPilot(bundle, (string)row["approvalDigest"],
                        File.ReadAllBytes((string)row["executable"]), File.ReadAllBytes((string)row["entryPoint"]),
                        (string)row["endpoint"], now);
                    if (row.ContainsKey("execute") && (bool)row["execute"])
                    {
                        string root = CSA.Collector.Program.CreateRestrictedTemporaryDirectory();
                        List<FileStream> leases = new List<FileStream>();
                        try
                        {
                            byte[] archive = File.ReadAllBytes(Path.Combine(bundle, "collector.zip"));
                            CSA.Collector.Program.ExtractVerifiedArchive(archive, root);
                            CSA.Collector.Program.VerifyTrustedConfiguration(root, metadata.Session);
                            CSA.Collector.Program.LeaseVerifiedFiles(archive, root, leases);
                            Protocol.Require(CSA.Collector.Program.RunPowerShell(root, row.ContainsKey("offlineOutput"),
                                row.ContainsKey("offlineOutput") ? (string)row["offlineOutput"] : null, true, (bool)row["quick"]) == 0, "FIXTURE-COLLECTION-FAILED");
                        }
                        finally
                        {
                            foreach (FileStream lease in leases) lease.Dispose();
                            Protocol.Require(CSA.Collector.Program.RemoveTemporaryDirectory(root), "FIXTURE-CLEANUP-FAILED");
                        }
                    }
                    outcomes.Add("PASS");
                    continue;
                }
                if (kind == "inspect" || kind == "network")
                {
                    Dictionary<string, object> policy = Protocol.Policy(Convert.FromBase64String((string)row["policy"]), now);
                    byte[] executable = Convert.FromBase64String((string)row["executable"]);
                    byte[] entry = Convert.FromBase64String((string)row["entryPoint"]);
                    if (kind == "inspect")
                    {
                        string bundle = (string)row["root"];
                        BundleMetadata metadata = BundleMetadata.Verify(policy,
                            File.ReadAllBytes(Path.Combine(bundle, "publisher-manifest.json")), File.ReadAllBytes(Path.Combine(bundle, "publisher-manifest.p7s")),
                            File.ReadAllBytes(Path.Combine(bundle, "session-envelope.json")), File.ReadAllBytes(Path.Combine(bundle, "session-envelope.p7s")),
                            executable, entry, now);
                        Dictionary<string, object> facts = CSA.Collector.Program.InspectAuthenticatedBundle(bundle, metadata, policy);
                        facts["policyDigest"] = Protocol.Digest(Convert.FromBase64String((string)row["policy"]));
                        facts["approvalDigest"] = Protocol.Digest(Encoding.UTF8.GetBytes("ISOLATED TEST ONLY"));
                        facts["approvalState"] = "TEST_ONLY";
                        outcomes.Add(new Dictionary<string, object> { { "assurance", "TEST_ONLY" }, { "facts", facts } });
                    }
                    else
                    {
                        List<string> phases = new List<string>();
                        NetworkBundle acquired = NetworkBootstrap.Acquire(policy, (string)row["labId"], (string)row["envelopeId"],
                            executable, entry, () => Console.In.ReadLine(), code => phases.Add(code), (string)row["requestedMode"]);
                        if (row.ContainsKey("execute") && (bool)row["execute"])
                        {
                            string root = CSA.Collector.Program.CreateRestrictedTemporaryDirectory();
                            List<FileStream> leases = new List<FileStream>();
                            try
                            {
                                CSA.Collector.Program.ExtractVerifiedArchive(acquired.Archive, root);
                                CSA.Collector.Program.VerifyTrustedConfiguration(root, acquired.Metadata.Session);
                                CSA.Collector.Program.LeaseVerifiedFiles(acquired.Archive, root, leases);
                                int result = CSA.Collector.Program.RunPowerShell(root, false, null, true,
                                    (string)row["requestedMode"] == "QUICK_RUN_PROCESS_BYPASS");
                                Protocol.Require(result == 0, "FIXTURE-COLLECTION-FAILED");
                            }
                            finally
                            {
                                foreach (FileStream lease in leases) lease.Dispose();
                                Protocol.Require(CSA.Collector.Program.RemoveTemporaryDirectory(root), "FIXTURE-CLEANUP-FAILED");
                            }
                        }
                        outcomes.Add(new Dictionary<string, object> { { "status", "PASS" }, { "archiveDigest", Protocol.Digest(acquired.Archive) },
                            { "phases", phases.ToArray() }, { "envelopeId", acquired.Metadata.Session["envelopeId"] } });
                    }
                    continue;
                }
                if (kind == "canonical") Protocol.ReadCanonical(Convert.FromBase64String((string)row["content"]));
                else if (kind == "organizationPolicy")
                    CSA.Collector.Program.VerifyEnforcedScriptPolicy(row["machineEnabled"], row["machinePolicy"], row["userEnabled"], row["userPolicy"]);
                else if (kind == "configuration") CSA.Collector.Program.VerifyTrustedConfiguration((string)row["root"],
                    Protocol.ReadCanonical(Convert.FromBase64String((string)row["session"])));
                else if (kind == "leases")
                {
                    List<FileStream> leases = new List<FileStream>();
                    try { CSA.Collector.Program.LeaseVerifiedFiles(Convert.FromBase64String((string)row["content"]), (string)row["root"], leases); }
                    finally { foreach (FileStream lease in leases) lease.Dispose(); }
                }
                else if (kind == "artifact") Protocol.Artifact(Convert.FromBase64String((string)row["content"]), (string)row["expected"]);
                else if (kind == "archive") Protocol.VerifyArchive(Convert.FromBase64String((string)row["content"]),
                    Protocol.ReadCanonical(Convert.FromBase64String((string)row["release"])),
                    Protocol.ReadCanonical(Convert.FromBase64String((string)row["session"])));
                else if (kind == "signature") Protocol.VerifySigned(
                    Convert.FromBase64String((string)row["content"]), Convert.FromBase64String((string)row["signature"]),
                    Protocol.Policy(Convert.FromBase64String((string)row["policy"]), now), (string)row["role"], now);
                else Protocol.Policy(Convert.FromBase64String((string)row["content"]), now);
                outcomes.Add("PASS");
            }
            catch (TrustFailure error) { outcomes.Add(error.Message); }
            catch (TransientTransportFailure) { outcomes.Add("CSA-NETWORK-INTERRUPTED"); }
            catch { outcomes.Add("INVALID_INPUT"); }
        }
        Console.WriteLine(json.Serialize(outcomes));
        return 0;
    }
}
