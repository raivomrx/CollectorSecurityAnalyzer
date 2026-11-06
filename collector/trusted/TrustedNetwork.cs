using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using CSA.Trust;

namespace CSA.Trust
{
    public sealed class NetworkBundle
    {
        public BundleMetadata Metadata;
        public byte[] Archive;
        public Dictionary<string, byte[]> Files;
    }

    public sealed class TransientTransportFailure : Exception { }

    public static class NetworkBootstrap
    {
        public static bool Locator(string value) { return value != null && Regex.IsMatch(value, "\\A[A-Za-z0-9_-]{16,128}\\z"); }

        public static NetworkBundle Acquire(Dictionary<string, object> policy, string labId, string envelopeId,
            byte[] executable, byte[] entryPoint, Func<string> promptSecret, Action<string> phase, string requestedMode = "STANDARD_POLICY")
        {
            Protocol.Require(Regex.IsMatch(labId ?? "", "\\A[A-Za-z0-9_-]{8,128}\\z") && Locator(envelopeId), "CSA-TRUST-LOCATOR");
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Dictionary<string, object>[] labs = Protocol.Rows(policy, "labs").Select(Protocol.Object)
                .Where(row => Protocol.Text(row, "labId") == labId && !(bool)row["revoked"]
                    && Protocol.Number(row, "issuedAt") <= now + 120 && Protocol.Number(row, "expiresAt") > now).ToArray();
            Protocol.Require(labs.Length > 0 && labs.Select(row => Protocol.Text(row, "origin")).Distinct().Count() == 1
                && labs.Select(row => Protocol.Text(row, "tlsFingerprint")).Distinct().Count() == 1, "CSA-TRUST-LAB");
            string origin = Protocol.Text(labs[0], "origin"), pin = Protocol.Text(labs[0], "tlsFingerprint");
            Protocol.Origin(origin);
            string endpoint = origin + "/api/v2/trusted/" + envelopeId + "/";
            phase("TRUST_METADATA");
            Dictionary<string, object> descriptor = Json(Call(endpoint + "metadata", "GET", null, null, 4 * 1024 * 1024, pin, true));
            Protocol.Fields(descriptor, "publisherManifest", "publisherSignature", "sessionEnvelope", "sessionSignature");
            Dictionary<string, byte[]> files = new Dictionary<string, byte[]> {
                { "publisher-manifest.json", Decode(descriptor, "publisherManifest", 2 * 1024 * 1024) },
                { "publisher-manifest.p7s", Decode(descriptor, "publisherSignature", 65536) },
                { "session-envelope.json", Decode(descriptor, "sessionEnvelope", 1024 * 1024) },
                { "session-envelope.p7s", Decode(descriptor, "sessionSignature", 65536) }
            };
            BundleMetadata metadata = BundleMetadata.Verify(policy, files["publisher-manifest.json"], files["publisher-manifest.p7s"],
                files["session-envelope.json"], files["session-envelope.p7s"], executable, entryPoint, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            Protocol.Require(Protocol.Number(metadata.Session, "schemaVersion") == 2
                && Protocol.Text(metadata.Session, "envelopeId") == envelopeId && Protocol.Text(metadata.Session, "labId") == labId,
                "CSA-TRUST-SESSION");
            phase("TRUST_AUTHORIZATION");
            Dictionary<string, object> challenge = Json(Call(endpoint + "challenge", "GET", null, null, 16384, pin, true));
            Protocol.Fields(challenge, "challengeId", "nonce", "envelopeId", "recipientId", "assessmentId", "sessionId", "envelopeDigest", "purpose", "expiresAt");
            foreach (string key in new[] { "envelopeId", "recipientId", "assessmentId", "sessionId" })
                Protocol.Require(Protocol.Text(challenge, key) == Protocol.Text(metadata.Session, key), "CSA-TRUST-CHALLENGE");
            Protocol.Require(Locator(Protocol.Text(challenge, "challengeId")) && Locator(Protocol.Text(challenge, "nonce"))
                && Protocol.Text(challenge, "envelopeDigest") == Protocol.Digest(metadata.SessionBytes)
                && Protocol.Text(challenge, "purpose") == "COLLECTOR_DOWNLOAD", "CSA-TRUST-CHALLENGE");
            Fresh(challenge, 90);
            // No credential is requested before independent publisher/Lab/scope/TLS verification.
            CheckCurrentTrust(policy, metadata);
            string secret = promptSecret();
            Protocol.Require(Locator(secret), "CSA-TRUST-AUTHORIZATION");
            Dictionary<string, object> authorization;
            try
            {
                CheckCurrentTrust(policy, metadata);
                Fresh(challenge, 90);
                authorization = Json(Call(endpoint + "authorize", "POST", new Dictionary<string, object> {
                    { "challengeId", challenge["challengeId"] }, { "nonce", challenge["nonce"] },
                    { "recipientId", challenge["recipientId"] }, { "envelopeDigest", challenge["envelopeDigest"] },
                    { "requestedMode", requestedMode }
                }, "CSA-Assessor " + secret, 16384, pin, false));
            }
            finally { secret = null; }
            Protocol.Fields(authorization, "authorizationTicket", "envelopeId", "expiresAt");
            Protocol.Require(Protocol.Text(authorization, "envelopeId") == envelopeId && Locator(Protocol.Text(authorization, "authorizationTicket")), "CSA-TRUST-AUTHORIZATION");
            Fresh(authorization, 120);
            phase("TRUST_PACKAGE_DOWNLOAD");
            byte[] archive = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                Dictionary<string, object> grant = Json(Call(endpoint + "download-grant", "POST", new Dictionary<string, object>(),
                    "CSA-Authorization " + Protocol.Text(authorization, "authorizationTicket"), 16384, pin, false));
                Protocol.Fields(grant, "downloadGrant", "envelopeId", "expiresAt");
                Protocol.Require(Protocol.Text(grant, "envelopeId") == envelopeId && Locator(Protocol.Text(grant, "downloadGrant")), "CSA-TRUST-DOWNLOAD");
                Fresh(grant, 45);
                try
                {
                    archive = Call(endpoint + "package", "POST", null, "CSA-Download " + Protocol.Text(grant, "downloadGrant"),
                        64 * 1024 * 1024, pin, false);
                    break;
                }
                catch (TransientTransportFailure)
                {
                    if (attempt == 2) throw new TrustFailure("CSA-NETWORK-INTERRUPTED");
                    phase("TRUST_DOWNLOAD_RETRY");
                    Thread.Sleep(250 * (attempt + 1));
                }
            }
            Protocol.Require(archive != null, "CSA-NETWORK-INTERRUPTED");
            // A complete but wrong body is a trust failure, not a transport retry.
            Protocol.VerifyArchive(archive, metadata.Release, metadata.Session);
            CheckCurrentTrust(policy, metadata);
            files.Add("collector.zip", archive);
            return new NetworkBundle { Metadata = metadata, Archive = archive, Files = files };
        }

        private static void CheckCurrentTrust(Dictionary<string, object> policy, BundleMetadata metadata)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Protocol.Window(policy, now);
            Protocol.Require(Protocol.Number(policy, "revocationFreshUntil") > now, "CSA-TRUST-STALE");
            Protocol.Window(metadata.Release, now);
            Protocol.Window(metadata.Session, now);
            Protocol.Window(Protocol.Key(policy, "publishers", Protocol.Text(metadata.Release, "keyId"), now), now);
            Protocol.Window(Protocol.Key(policy, "labs", Protocol.Text(metadata.Session, "keyId"), now), now);
        }

        private static void Fresh(Dictionary<string, object> value, int maximumSeconds)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), expiry = Protocol.Number(value, "expiresAt");
            Protocol.Require(expiry > now && expiry <= now + maximumSeconds + 2, "CSA-TRUST-EXPIRED");
        }

        private static Dictionary<string, object> Json(byte[] bytes) { return Protocol.ReadCanonical(bytes); }
        private static byte[] Decode(Dictionary<string, object> value, string key, int maximum)
        {
            try
            {
                object item;
                Protocol.Require(value.TryGetValue(key, out item) && item is string, "CSA-TRUST-JSON");
                byte[] bytes = Convert.FromBase64String((string)item);
                Protocol.Require(bytes.Length <= maximum, "CSA-TRUST-SIZE");
                return bytes;
            }
            catch (TrustFailure) { throw; }
            catch { throw new TrustFailure("CSA-TRUST-JSON"); }
        }

        private static byte[] Call(string url, string method, Dictionary<string, object> body, string authorization,
            int maximum, string pin, bool retry)
        {
            for (int attempt = 0; ; attempt++)
            {
                try { return Request(url, method, body, authorization, maximum, pin); }
                catch (TransientTransportFailure)
                {
                    if (!retry || attempt >= 2) throw;
                    Thread.Sleep(250 * (attempt + 1));
                }
            }
        }

        private static byte[] Request(string url, string method, Dictionary<string, object> body, string authorization, int maximum, string pin)
        {
            bool wrongCertificate = false;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method;
            request.AllowAutoRedirect = false;
            request.KeepAlive = false;
            request.Proxy = null;
            request.Timeout = 15000;
            request.ReadWriteTimeout = 15000;
            request.ServerCertificateValidationCallback = (sender, certificate, chain, errors) => {
                X509Certificate2 leaf = certificate as X509Certificate2;
                bool accepted = leaf != null && Protocol.Digest(leaf.RawData) == pin
                    && leaf.NotBefore <= DateTime.Now && leaf.NotAfter >= DateTime.Now;
                if (!accepted) wrongCertificate = true;
                return accepted;
            };
            if (authorization != null) request.Headers[HttpRequestHeader.Authorization] = authorization;
            byte[] payload = body == null ? new byte[0] : Encoding.UTF8.GetBytes(Protocol.Canonical(body));
            if (method == "POST") { request.ContentType = "application/json"; request.ContentLength = payload.Length; }
            int timedOut = 0;
            using (Timer timer = new Timer(_ => { Interlocked.Exchange(ref timedOut, 1); request.Abort(); }, null, 20000, Timeout.Infinite))
            try
            {
                if (payload.Length > 0) using (Stream output = request.GetRequestStream()) output.Write(payload, 0, payload.Length);
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    Protocol.Require(response.StatusCode == HttpStatusCode.OK && response.ContentLength >= 0
                        && response.ContentLength <= maximum, "CSA-TRUST-HTTP");
                    byte[] bytes;
                    using (Stream input = response.GetResponseStream()) bytes = Protocol.ReadBounded(input, maximum);
                    if (bytes.LongLength != response.ContentLength) throw new TransientTransportFailure();
                    return bytes;
                }
            }
            catch (WebException error)
            {
                if (error.Response != null) error.Response.Dispose();
                if (wrongCertificate || error.Status == WebExceptionStatus.TrustFailure || error.Status == WebExceptionStatus.SecureChannelFailure)
                    throw new TrustFailure("CSA-TRUST-TLS");
                if (Interlocked.CompareExchange(ref timedOut, 0, 0) != 0 || error.Status == WebExceptionStatus.Timeout || error.Status == WebExceptionStatus.ConnectFailure
                    || error.Status == WebExceptionStatus.ConnectionClosed || error.Status == WebExceptionStatus.ReceiveFailure
                    || error.Status == WebExceptionStatus.SendFailure) throw new TransientTransportFailure();
                throw new TrustFailure("CSA-TRUST-HTTP");
            }
            catch (IOException) { throw new TransientTransportFailure(); }
            finally { request.Abort(); }
        }
    }
}
