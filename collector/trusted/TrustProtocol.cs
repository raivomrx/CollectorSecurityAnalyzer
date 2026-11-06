using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace CSA.Trust
{
    public sealed class TrustFailure : Exception
    {
        public TrustFailure(string code) : base(code) { }
    }

    public static class Protocol
    {
        public static void Require(bool valid, string code)
        {
            if (!valid) throw new TrustFailure(code);
        }

        public static string Digest(byte[] bytes)
        {
            using (SHA256 hash = SHA256.Create())
                return "sha256:" + BitConverter.ToString(hash.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }

        // The signed schemas use the integer-only JCS subset. Floating-point
        // numbers and noncanonical input are refused, including duplicate keys.
        public static Dictionary<string, object> ReadCanonical(byte[] bytes)
        {
            Require(bytes.Length > 0 && bytes.Length <= 4 * 1024 * 1024, "CSA-TRUST-JSON");
            try
            {
                string text = new UTF8Encoding(false, true).GetString(bytes);
                JavaScriptSerializer parser = new JavaScriptSerializer { MaxJsonLength = 4 * 1024 * 1024, RecursionLimit = 32 };
                object value = parser.DeserializeObject(text);
                Require(text == Canonical(value), "CSA-TRUST-CANONICAL");
                Dictionary<string, object> result = value as Dictionary<string, object>;
                Require(result != null, "CSA-TRUST-JSON");
                return result;
            }
            catch (TrustFailure) { throw; }
            catch { throw new TrustFailure("CSA-TRUST-JSON"); }
        }

        public static string Canonical(object value)
        {
            if (value == null) return "null";
            string text = value as string;
            if (text != null)
            {
                new UTF8Encoding(false, true).GetBytes(text);
                StringBuilder result = new StringBuilder("\"");
                foreach (char character in text)
                {
                    switch (character)
                    {
                        case '"': result.Append("\\\""); break;
                        case '\\': result.Append("\\\\"); break;
                        case '\b': result.Append("\\b"); break;
                        case '\t': result.Append("\\t"); break;
                        case '\n': result.Append("\\n"); break;
                        case '\f': result.Append("\\f"); break;
                        case '\r': result.Append("\\r"); break;
                        default:
                            result.Append(character < 32 ? "\\u" + ((int)character).ToString("x4") : character.ToString());
                            break;
                    }
                }
                return result.Append('"').ToString();
            }
            if (value is bool) return (bool)value ? "true" : "false";
            if (value is int || value is long)
            {
                long number = Convert.ToInt64(value);
                Require(number >= -9007199254740991L && number <= 9007199254740991L, "CSA-TRUST-NUMBER");
                return number.ToString(CultureInfo.InvariantCulture);
            }
            IDictionary<string, object> dictionary = value as IDictionary<string, object>;
            if (dictionary != null)
                return "{" + String.Join(",", dictionary.Keys.OrderBy(key => key, StringComparer.Ordinal)
                    .Select(key => Canonical(key) + ":" + Canonical(dictionary[key]))) + "}";
            if (value is object[])
                return "[" + String.Join(",", ((object[])value).Select(Canonical)) + "]";
            throw new TrustFailure("CSA-TRUST-NUMBER");
        }

        public static void Fields(Dictionary<string, object> value, params string[] fields)
        {
            Require(new HashSet<string>(fields, StringComparer.Ordinal).SetEquals(value.Keys), "CSA-TRUST-SCHEMA");
        }

        public static string Text(Dictionary<string, object> value, string key)
        {
            object item;
            Require(value.TryGetValue(key, out item) && item is string && ((string)item).Length <= 4096, "CSA-TRUST-SCHEMA");
            return (string)item;
        }

        public static long Number(Dictionary<string, object> value, string key)
        {
            object item;
            Require(value.TryGetValue(key, out item) && (item is int || item is long), "CSA-TRUST-SCHEMA");
            return Convert.ToInt64(item);
        }

        public static object[] Rows(Dictionary<string, object> value, string key)
        {
            object item;
            Require(value.TryGetValue(key, out item) && item is object[], "CSA-TRUST-SCHEMA");
            return (object[])item;
        }

        public static Dictionary<string, object> Object(object value)
        {
            Require(value is Dictionary<string, object>, "CSA-TRUST-SCHEMA");
            return (Dictionary<string, object>)value;
        }

        public static void Window(Dictionary<string, object> value, long now)
        {
            long issued = Number(value, "issuedAt"), expires = Number(value, "expiresAt");
            Require(issued <= now + 120 && issued < expires && now < expires, "CSA-TRUST-EXPIRED");
        }

        public static Dictionary<string, object> Policy(byte[] bytes, long now)
        {
            Dictionary<string, object> policy = ReadCanonical(bytes);
            Fields(policy, "objectType", "schemaVersion", "issuedAt", "expiresAt", "revocationFreshUntil",
                "minimumReleaseSequence", "endpointId", "publishers", "labs");
            Require(Text(policy, "objectType") == "CSA_TRUST_POLICY" && Number(policy, "schemaVersion") == 1, "CSA-TRUST-SCHEMA");
            Window(policy, now);
            Require(Number(policy, "revocationFreshUntil") > now && Number(policy, "revocationFreshUntil") <= Number(policy, "expiresAt"),
                "CSA-TRUST-STALE");
            Require(Regex.IsMatch(Text(policy, "endpointId"), "\\A[A-Za-z0-9_-]{16,128}\\z"), "CSA-TRUST-RECIPIENT");
            Require(Number(policy, "minimumReleaseSequence") >= 1, "CSA-TRUST-ROLLBACK");
            Require(Rows(policy, "publishers").Length > 0 && Rows(policy, "labs").Length > 0, "TRUST_NOT_ESTABLISHED");
            foreach (string role in new[] { "publishers", "labs" })
            {
                HashSet<string> identifiers = new HashSet<string>(StringComparer.Ordinal);
                foreach (object item in Rows(policy, role))
                {
                    Dictionary<string, object> key = Object(item);
                    KeyFields(key, role);
                    Require(identifiers.Add(Text(key, "keyId")) && Regex.IsMatch(Text(key, "keyId"), "\\A[A-Za-z0-9_-]{3,128}\\z"), "CSA-TRUST-KEY");
                    HashValue(Text(key, "spkiSha256"));
                    Require(key["revoked"] is bool && Number(key, "issuedAt") < Number(key, "expiresAt"), "CSA-TRUST-SCHEMA");
                    if (role == "publishers") HashValue(Text(key, "certificateSha256"));
                    else
                    {
                        Origin(Text(key, "origin")); HashValue(Text(key, "tlsFingerprint"));
                        Require(Regex.IsMatch(Text(key, "labId"), "\\A[A-Za-z0-9_-]{8,128}\\z"), "CSA-TRUST-LAB");
                    }
                }
            }
            Require(!Rows(policy, "publishers").Select(Object).Select(item => Text(item, "spkiSha256"))
                .Intersect(Rows(policy, "labs").Select(Object).Select(item => Text(item, "spkiSha256"))).Any(), "CSA-TRUST-ROLES");
            return policy;
        }

        public static Dictionary<string, object> Key(Dictionary<string, object> policy, string role, string id, long now)
        {
            Dictionary<string, object>[] matches = Rows(policy, role).Select(Object)
                .Where(item => Text(item, "keyId") == id).ToArray();
            Require(matches.Length == 1, "CSA-TRUST-KEY");
            Dictionary<string, object> key = matches[0];
            KeyFields(key, role);
            Require(key.ContainsKey("revoked") && key["revoked"] is bool && !(bool)key["revoked"], "CSA-TRUST-REVOKED");
            Window(key, now);
            return key;
        }

        private static void KeyFields(Dictionary<string, object> key, string role)
        {
            Require(role == "publishers" || role == "labs", "CSA-TRUST-ROLE");
            if (role == "publishers")
                Fields(key, "keyId", "spkiSha256", "certificateSha256", "issuedAt", "expiresAt", "revoked");
            else
                Fields(key, "keyId", "spkiSha256", "issuedAt", "expiresAt", "revoked", "labId", "origin", "tlsFingerprint");
        }

        private static void HashValue(string value)
        {
            Require(Regex.IsMatch(value, "\\Asha256:[0-9a-f]{64}\\z"), "CSA-TRUST-SCHEMA");
        }

        public static Dictionary<string, object> VerifySigned(
            byte[] bytes, byte[] signature, Dictionary<string, object> policy, string role, long now)
        {
            Dictionary<string, object> value = ReadCanonical(bytes);
            Require(signature.Length > 0 && signature.Length <= 65536, "CSA-TRUST-SIGNATURE");
            Dictionary<string, object> key = Key(policy, role, Text(value, "keyId"), now);
            try
            {
                SignedCms cms = new SignedCms(new ContentInfo(bytes), true);
                cms.Decode(signature);
                Require(cms.Detached && cms.SignerInfos.Count == 1, "CSA-TRUST-SIGNATURE");
                SignerInfo signer = cms.SignerInfos[0];
                Require(signer.DigestAlgorithm.Value == "2.16.840.1.101.3.4.2.1"
                    && signer.SignatureAlgorithm.Value == "1.2.840.113549.1.1.1", "CSA-TRUST-ALGORITHM");
                cms.CheckSignature(true);
                X509Certificate2 certificate = signer.Certificate;
                Require(certificate != null && certificate.NotBefore.ToUniversalTime() <= DateTimeOffset.FromUnixTimeSeconds(now).UtcDateTime
                    && certificate.NotAfter.ToUniversalTime() > DateTimeOffset.FromUnixTimeSeconds(now).UtcDateTime, "CSA-TRUST-CERTIFICATE");
                using (RSA rsa = certificate.GetRSAPublicKey())
                    Require(rsa != null && rsa.KeySize >= 3072 && SpkiDigest(rsa) == Text(key, "spkiSha256"), "CSA-TRUST-SIGNER");
                if (role == "publishers")
                    Require(Digest(certificate.RawData) == Text(key, "certificateSha256"), "CSA-TRUST-SIGNER");
            }
            catch (TrustFailure) { throw; }
            catch { throw new TrustFailure("CSA-TRUST-SIGNATURE"); }
            Window(value, now);
            Require(Number(value, "schemaVersion") == 1 || role == "labs" && Number(value, "schemaVersion") == 2, "CSA-TRUST-SCHEMA");
            if (role == "publishers")
            {
                Fields(value, "objectType", "schemaVersion", "keyId", "issuedAt", "expiresAt", "releaseSequence",
                    "version", "commit", "bootstrapSha256", "bootstrapSize", "entryPointSha256", "entryPointSize", "files", "profiles");
                Require(Text(value, "objectType") == "CSA_PUBLISHER_RELEASE", "CSA-TRUST-ROLE");
                Require(Regex.IsMatch(Text(value, "version"), "\\A[A-Za-z0-9._-]{1,64}\\z")
                    && Regex.IsMatch(Text(value, "commit"), "\\A[0-9a-f]{40}\\z"), "CSA-TRUST-SCHEMA");
                Require(Number(value, "bootstrapSize") > 0 && Number(value, "bootstrapSize") <= 16 * 1024 * 1024
                    && Number(value, "entryPointSize") > 0 && Number(value, "entryPointSize") <= 1024 * 1024, "CSA-TRUST-SIZE");
                Require(Number(value, "releaseSequence") >= Number(policy, "minimumReleaseSequence"), "CSA-TRUST-ROLLBACK");
            }
            else
            {
                Fields(value, "objectType", "schemaVersion", "keyId", "issuedAt", "expiresAt", "envelopeId",
                    "labId", "recipientId", "assessmentId", "sessionId", "origin", "tlsFingerprint", "mode",
                    "profileId", "profileDigest", "privacyPolicyDigest", "publisherManifestDigest",
                    "packageDigest", "sessionManifestDigest", "nonce", "submissionPolicy");
                Require(Text(value, "objectType") == "CSA_LAB_SESSION", "CSA-TRUST-ROLE");
                foreach (string field in new[] { "labId", "origin", "tlsFingerprint" })
                    Require(Text(value, field) == Text(key, field), "CSA-TRUST-LAB");
                Require(Text(value, "recipientId") == Text(policy, "endpointId"), "CSA-TRUST-RECIPIENT");
                Origin(Text(value, "origin"));
                Require(Text(value, "mode") == "STANDARD_USER_COLLECTION"
                    && Number(value, "expiresAt") - Number(value, "issuedAt") <= 86400, "CSA-TRUST-SCOPE");
                Require(Regex.IsMatch(Text(value, "envelopeId"), "\\A[A-Za-z0-9_-]{16,128}\\z")
                    && Regex.IsMatch(Text(value, "nonce"), "\\A[A-Za-z0-9_-]{16,128}\\z"), "CSA-TRUST-NONCE");
            }
            return value;
        }

        // RSA SubjectPublicKeyInfo DER, matching RFC 5280 and the enrolled pin.
        public static string SpkiDigest(RSA rsa)
        {
            RSAParameters key = rsa.ExportParameters(false);
            byte[] algorithm = { 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] modulus = key.Modulus[0] >= 128 ? new byte[] { 0 }.Concat(key.Modulus).ToArray() : key.Modulus;
            byte[] encoded = Der(0x30, Der(2, modulus).Concat(Der(2, key.Exponent)).ToArray());
            return Digest(Der(0x30, algorithm.Concat(Der(3, new byte[] { 0 }.Concat(encoded).ToArray())).ToArray()));
        }

        private static byte[] Der(byte tag, byte[] value)
        {
            List<byte> result = new List<byte> { tag };
            if (value.Length < 128) result.Add((byte)value.Length);
            else
            {
                byte[] length = BitConverter.GetBytes(value.Length).Reverse().SkipWhile(part => part == 0).ToArray();
                result.Add((byte)(128 + length.Length));
                result.AddRange(length);
            }
            result.AddRange(value);
            return result.ToArray();
        }

        public static void ProtectedPath(string path)
        {
            string full = Path.GetFullPath(path);
            string[] trusted = { "S-1-5-18", "S-1-5-32-544" };
            bool reachedRoot = false;
            for (string current = full; current != null; current = Path.GetDirectoryName(current))
            {
                Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "CSA-TRUST-POLICY-PATH");
                if (String.Equals(current, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    StringComparison.OrdinalIgnoreCase) || String.Equals(current,
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase))
                {
                    reachedRoot = true;
                    break;
                }
                FileSystemSecurity acl = Directory.Exists(current)
                    ? (FileSystemSecurity)Directory.GetAccessControl(current) : File.GetAccessControl(current);
                Require(trusted.Contains(acl.GetOwner(typeof(SecurityIdentifier)).Value), "CSA-TRUST-POLICY-ACL");
                foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    FileSystemRights writes = FileSystemRights.WriteData | FileSystemRights.AppendData
                        | FileSystemRights.WriteAttributes | FileSystemRights.WriteExtendedAttributes
                        | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
                        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
                    Require(rule.AccessControlType != AccessControlType.Allow || (rule.FileSystemRights & writes) == 0
                        || trusted.Contains(rule.IdentityReference.Value), "CSA-TRUST-POLICY-ACL");
                }
            }
            Require(reachedRoot, "CSA-TRUST-INSTALLATION");
        }

        public static void VerifyArchive(byte[] bytes, Dictionary<string, object> release, Dictionary<string, object> session)
        {
            Require(Digest(bytes) == Text(session, "packageDigest"), "CSA-TRUST-DIGEST");
            VerifyProfile(release, session);
            Dictionary<string, Dictionary<string, object>> engine = EngineInventory(release);
            HashSet<string> data = new HashSet<string>(new[] { "session-config.json", "server-cert.pem", "offline-public.xml", "OPERATOR-INSTRUCTIONS.txt" }, StringComparer.Ordinal);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long size = 0;
            using (MemoryStream memory = new MemoryStream(bytes, false))
            using (ZipArchive archive = new ZipArchive(memory, ZipArchiveMode.Read, false))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    SafePath(entry.FullName);
                    Require(seen.Add(entry.FullName) && entry.Length <= 32 * 1024 * 1024, "CSA-TRUST-PATH");
                    size += entry.Length;
                    Require(size <= 128 * 1024 * 1024, "CSA-TRUST-SIZE");
                    byte[] content;
                    using (Stream input = entry.Open()) content = ReadBounded(input, 32 * 1024 * 1024);
                    if (entry.FullName == "trusted-manifest.json")
                        Require(Digest(content) == Text(session, "sessionManifestDigest"), "CSA-TRUST-DIGEST");
                    else if (engine.ContainsKey(entry.FullName))
                    {
                        Dictionary<string, object> file = engine[entry.FullName];
                        Require(entry.FullName == Text(file, "path") && content.LongLength == Number(file, "size")
                            && Digest(content) == Text(file, "sha256"), "CSA-TRUST-ENGINE");
                    }
                    else Require(data.Contains(entry.FullName), "CSA-TRUST-UNEXPECTED-FILE");
                }
            }
            Require(engine.Keys.All(seen.Contains) && data.All(seen.Contains) && seen.Contains("trusted-manifest.json"), "CSA-TRUST-MISSING-FILE");
        }

        public static void VerifyProfile(Dictionary<string, object> release, Dictionary<string, object> session)
        {
            foreach (object item in Rows(release, "profiles"))
                Fields(Object(item), "profileId", "profileDigest", "privacyPolicyDigest");
            Dictionary<string, object>[] profiles = Rows(release, "profiles").Select(Object)
                .Where(item => Text(item, "profileId") == Text(session, "profileId")).ToArray();
            Require(profiles.Length == 1, "CSA-TRUST-PROFILE");
            Fields(profiles[0], "profileId", "profileDigest", "privacyPolicyDigest");
            Require(Text(profiles[0], "profileDigest") == Text(session, "profileDigest")
                && Text(profiles[0], "privacyPolicyDigest") == Text(session, "privacyPolicyDigest"), "CSA-TRUST-PROFILE");
        }

        public static Dictionary<string, Dictionary<string, object>> EngineInventory(Dictionary<string, object> release)
        {
            Dictionary<string, Dictionary<string, object>> engine = new Dictionary<string, Dictionary<string, object>>(StringComparer.OrdinalIgnoreCase);
            foreach (object item in Rows(release, "files"))
            {
                Dictionary<string, object> file = Object(item);
                Fields(file, "path", "size", "sha256");
                string name = Text(file, "path");
                SafePath(name);
                Require(Number(file, "size") >= 0 && Number(file, "size") <= 32 * 1024 * 1024, "CSA-TRUST-SIZE");
                HashValue(Text(file, "sha256"));
                Require(name != "trusted-manifest.json" && !new[] { "session-config.json", "server-cert.pem", "offline-public.xml", "OPERATOR-INSTRUCTIONS.txt" }
                    .Contains(name, StringComparer.OrdinalIgnoreCase), "CSA-TRUST-ENGINE");
                Require(!engine.ContainsKey(name), "CSA-TRUST-PATH");
                engine.Add(name, file);
            }
            Require(engine.ContainsKey("Invoke-CSACollector.ps1"), "CSA-TRUST-ENGINE");
            return engine;
        }

        public static void SafePath(string name)
        {
            Require(!String.IsNullOrEmpty(name) && name.Length < 240 && !Path.IsPathRooted(name)
                && !name.Contains("\\") && !name.Contains(":")
                && name.Split('/').All(part => part.Length > 0 && part != "." && part != ".."
                    && !part.EndsWith(".") && !part.EndsWith(" ") && part.IndexOfAny(Path.GetInvalidFileNameChars()) < 0
                    && !Regex.IsMatch(part, "^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])($|\\.)", RegexOptions.IgnoreCase)),
                "CSA-TRUST-PATH");
        }

        public static byte[] ReadBounded(Stream input, int maximum)
        {
            using (MemoryStream output = new MemoryStream())
            {
                byte[] buffer = new byte[81920];
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Require(output.Length + read <= maximum, "CSA-TRUST-SIZE");
                    output.Write(buffer, 0, read);
                }
                return output.ToArray();
            }
        }

        public static void Origin(string origin)
        {
            Uri uri;
            Require(Uri.TryCreate(origin, UriKind.Absolute, out uri) && uri.Scheme == "https"
                && uri.UserInfo == "" && uri.Query == "" && uri.Fragment == "" && uri.AbsolutePath == "/"
                && origin == uri.GetLeftPart(UriPartial.Authority), "CSA-TRUST-ORIGIN");
        }

        public static void Artifact(byte[] bytes, string expected)
        {
            Require(Digest(bytes) == expected, "CSA-TRUST-BOOTSTRAP");
        }
    }

    public sealed class BundleMetadata
    {
        public Dictionary<string, object> Release;
        public Dictionary<string, object> Session;
        public byte[] PublisherBytes;
        public byte[] SessionBytes;
        public byte[] PublisherSignature;
        public byte[] SessionSignature;

        public static BundleMetadata Verify(Dictionary<string, object> policy, byte[] publisher, byte[] publisherSignature,
            byte[] session, byte[] sessionSignature, byte[] executable, byte[] entryPoint, long now)
        {
            Dictionary<string, object> release = Protocol.VerifySigned(publisher, publisherSignature, policy, "publishers", now);
            Protocol.Require(executable.LongLength == Protocol.Number(release, "bootstrapSize")
                && entryPoint.LongLength == Protocol.Number(release, "entryPointSize"), "CSA-TRUST-BOOTSTRAP");
            Protocol.Artifact(executable, Protocol.Text(release, "bootstrapSha256"));
            Protocol.Artifact(entryPoint, Protocol.Text(release, "entryPointSha256"));
            Dictionary<string, object> envelope = Protocol.VerifySigned(session, sessionSignature, policy, "labs", now);
            Protocol.Require(Protocol.Digest(publisher) == Protocol.Text(envelope, "publisherManifestDigest"), "CSA-TRUST-SESSION");
            Dictionary<string, object> submission = Protocol.Object(envelope["submissionPolicy"]);
            if (Protocol.Number(envelope, "schemaVersion") == 2)
            {
                Protocol.Fields(submission, "transport", "maximumBytes", "receiptRequired", "authorizationDigest");
                Protocol.Require(Regex.IsMatch(Protocol.Text(submission, "authorizationDigest"), "\\Asha256:[0-9a-f]{64}\\z"), "CSA-TRUST-AUTHORIZATION");
            }
            else Protocol.Fields(submission, "transport", "maximumBytes", "receiptRequired");
            Protocol.Require(Protocol.Text(submission, "transport") == "HTTPS_OR_ENCRYPTED_OFFLINE"
                && Protocol.Number(submission, "maximumBytes") > 0 && Protocol.Number(submission, "maximumBytes") <= 128 * 1024 * 1024
                && submission["receiptRequired"] is bool && (bool)submission["receiptRequired"], "CSA-TRUST-SCOPE");
            Protocol.VerifyProfile(release, envelope);
            Protocol.EngineInventory(release);
            return new BundleMetadata { Release = release, Session = envelope, PublisherBytes = publisher, SessionBytes = session,
                PublisherSignature = publisherSignature, SessionSignature = sessionSignature };
        }
    }
}
