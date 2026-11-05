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
        List<string> outcomes = new List<string>();
        foreach (object item in cases)
        {
            Dictionary<string, object> row = (Dictionary<string, object>)item;
            try
            {
                long now = Convert.ToInt64(row["now"]);
                string kind = (string)row["kind"];
                if (kind == "canonical") Protocol.ReadCanonical(Convert.FromBase64String((string)row["content"]));
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
            catch { outcomes.Add("INVALID_INPUT"); }
        }
        Console.WriteLine(json.Serialize(outcomes));
        return 0;
    }
}
