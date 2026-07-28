using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace CSA.Collector
{
    internal static class Program
    {
        private static readonly byte[] Magic = Encoding.ASCII.GetBytes("CSA51PKG");
        private const int TrailerSize = 48;

        private static int Main(string[] args)
        {
            string temporaryDirectory = null;
            try
            {
                Console.Title = "CSA Security Collector";
                WriteHeading();
                RejectElevatedProcess();
                temporaryDirectory = CreateRestrictedTemporaryDirectory();
                Console.WriteLine("Checking package integrity...");
                ExtractAndVerifyPackage(
                    Process.GetCurrentProcess().MainModule.FileName,
                    temporaryDirectory);
                PrintAssessmentSummary(temporaryDirectory);
                if (args.Length == 1 && args[0] == "--verify-only")
                {
                    Console.WriteLine("Collector package verification passed.");
                    return 0;
                }
                return RunCollectorWithRetry(temporaryDirectory);
            }
            catch (Exception error)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("CSA Collector could not complete.");
                Console.Error.WriteLine("Error code: CSA-COL-001");
                Console.Error.WriteLine(SafeMessage(error));
                WaitForUser();
                return 1;
            }
            finally
            {
                if (!String.IsNullOrEmpty(temporaryDirectory))
                {
                    Console.WriteLine("Cleaning temporary files...");
                    bool removed = RemoveTemporaryDirectory(temporaryDirectory);
                    Console.WriteLine(
                        "Local temporary data removed: " + (removed ? "YES" : "NO"));
                }
            }
        }

        private static void WriteHeading()
        {
            Console.WriteLine("CSA Security Collector");
            Console.WriteLine("======================");
            Console.WriteLine();
            Console.WriteLine("Mode: Standard User");
            Console.WriteLine("Administrator rights required: NO");
            Console.WriteLine("Active security testing: NO");
            Console.WriteLine();
            Console.WriteLine(
                "CSA collects system security configuration. CSA does not collect");
            Console.WriteLine(
                "passwords, browser credentials, private keys, recovery keys,");
            Console.WriteLine("or user document contents.");
            Console.WriteLine();
        }

        private static void RejectElevatedProcess()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (principal.IsInRole(WindowsBuiltInRole.Administrator) ||
                identity.IsSystem)
            {
                throw new InvalidOperationException(
                    "This standard-user Collector was started with elevated rights. " +
                    "Close it and run CSA-Collector.exe normally without Run as administrator.");
            }
        }

        private static string CreateRestrictedTemporaryDirectory()
        {
            string root = Path.Combine(Path.GetTempPath(), "CSA");
            Directory.CreateDirectory(root);
            string path = Path.Combine(root, "Collector-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);

            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            SecurityIdentifier current = WindowsIdentity.GetCurrent().User;
            security.AddAccessRule(new FileSystemAccessRule(
                current,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            Directory.SetAccessControl(path, security);
            return path;
        }

        private static void ExtractAndVerifyPackage(string executable, string target)
        {
            byte[] payload;
            using (FileStream stream = File.OpenRead(executable))
            {
                if (stream.Length <= TrailerSize)
                {
                    throw new InvalidDataException("Collector package is missing.");
                }
                stream.Seek(-TrailerSize, SeekOrigin.End);
                byte[] trailer = ReadExactly(stream, TrailerSize);
                long length = BitConverter.ToInt64(trailer, 0);
                byte[] expectedDigest = new byte[32];
                Buffer.BlockCopy(trailer, 8, expectedDigest, 0, 32);
                byte[] marker = new byte[Magic.Length];
                Buffer.BlockCopy(trailer, 40, marker, 0, marker.Length);
                if (!FixedTimeEquals(marker, Magic) ||
                    length <= 0 ||
                    length > stream.Length - TrailerSize)
                {
                    throw new InvalidDataException("Collector package binding is invalid.");
                }
                stream.Seek(stream.Length - TrailerSize - length, SeekOrigin.Begin);
                payload = ReadExactly(stream, checked((int)length));
                using (SHA256 sha = SHA256.Create())
                {
                    if (!FixedTimeEquals(sha.ComputeHash(payload), expectedDigest))
                    {
                        throw new InvalidDataException(
                            "Collector package digest verification failed.");
                    }
                }
            }

            using (MemoryStream memory = new MemoryStream(payload, false))
            using (ZipArchive archive = new ZipArchive(
                memory, ZipArchiveMode.Read, false))
            {
                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (String.IsNullOrEmpty(entry.Name))
                    {
                        continue;
                    }
                    string normalized = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                    if (Path.IsPathRooted(normalized) ||
                        normalized.Split(Path.DirectorySeparatorChar).Contains(".."))
                    {
                        throw new InvalidDataException(
                            "Collector package contains an unsafe path.");
                    }
                    string output = Path.GetFullPath(Path.Combine(target, normalized));
                    string prefix = Path.GetFullPath(target) + Path.DirectorySeparatorChar;
                    if (!output.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidDataException(
                            "Collector package path escapes its temporary directory.");
                    }
                    Directory.CreateDirectory(Path.GetDirectoryName(output));
                    using (Stream input = entry.Open())
                    using (FileStream destination = new FileStream(
                        output, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        input.CopyTo(destination);
                    }
                }
            }
            VerifyTrustedManifest(target);
        }

        private static void VerifyTrustedManifest(string root)
        {
            string manifestPath = Path.Combine(root, "trusted-manifest.json");
            if (!File.Exists(manifestPath))
            {
                throw new InvalidDataException("Trusted package manifest is missing.");
            }
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> manifest = serializer.Deserialize<
                Dictionary<string, object>>(File.ReadAllText(manifestPath, Encoding.UTF8));
            object filesValue;
            if (!manifest.TryGetValue("files", out filesValue))
            {
                throw new InvalidDataException("Trusted package file list is missing.");
            }
            ArrayList entries = filesValue as ArrayList;
            if (entries == null)
            {
                throw new InvalidDataException("Trusted package file list is invalid.");
            }
            HashSet<string> declared = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            foreach (object value in entries)
            {
                Dictionary<string, object> item = value as Dictionary<string, object>;
                if (item == null)
                {
                    throw new InvalidDataException("Trusted file entry is invalid.");
                }
                string relative = Convert.ToString(item["path"]);
                string expected = Convert.ToString(item["sha256"]);
                long expectedSize = Convert.ToInt64(item["size"]);
                if (!declared.Add(relative))
                {
                    throw new InvalidDataException("Trusted file path is duplicated.");
                }
                string path = ResolvePackagePath(root, relative);
                FileInfo file = new FileInfo(path);
                if (!file.Exists || file.Length != expectedSize ||
                    !String.Equals(Sha256File(path), expected,
                        StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException(
                        "Trusted Collector package verification failed.");
                }
            }
            HashSet<string> actual = new HashSet<string>(
                Directory.GetFiles(root, "*", SearchOption.AllDirectories)
                    .Where(path => !String.Equals(
                        Path.GetFileName(path),
                        "trusted-manifest.json",
                        StringComparison.OrdinalIgnoreCase))
                    .Select(path => path.Substring(root.Length + 1)
                        .Replace(Path.DirectorySeparatorChar, '/')),
                StringComparer.OrdinalIgnoreCase);
            if (!actual.SetEquals(declared))
            {
                throw new InvalidDataException(
                    "Collector package contains undeclared files.");
            }
        }

        private static void PrintAssessmentSummary(string root)
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            Dictionary<string, object> configuration = serializer.Deserialize<
                Dictionary<string, object>>(File.ReadAllText(
                    Path.Combine(root, "session-config.json"), Encoding.UTF8));
            Console.WriteLine("Assessment: " + Convert.ToString(
                configuration["assessmentName"]));
            Console.WriteLine("Server: " + SafeServer(
                Convert.ToString(configuration["serverUrl"])));
            Console.WriteLine();
        }

        private static int RunCollectorWithRetry(string root)
        {
            while (true)
            {
                Console.WriteLine("Starting security collection...");
                int exitCode = RunPowerShell(root, false, null);
                if (exitCode == 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("Collection completed.");
                    Console.WriteLine("Evidence accepted by CSA Lab.");
                    WaitForUser();
                    return 0;
                }
                Console.WriteLine();
                Console.WriteLine("CSA Lab could not accept the endpoint collection.");
                Console.WriteLine("Check that collection is running and both computers");
                Console.WriteLine("are on the same network.");
                Console.WriteLine();
                Console.Write("[R]etry, create [O]ffline package, or [C]ancel: ");
                string action = (Console.ReadLine() ?? "").Trim().ToUpperInvariant();
                if (action == "R")
                {
                    continue;
                }
                if (action == "O")
                {
                    string desktop = Environment.GetFolderPath(
                        Environment.SpecialFolder.DesktopDirectory);
                    string output = Path.Combine(
                        desktop,
                        "CSA-Offline-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + ".csa");
                    int offlineExit = RunPowerShell(root, true, output);
                    if (offlineExit == 0)
                    {
                        Console.WriteLine("Encrypted offline package created:");
                        Console.WriteLine(output);
                        WaitForUser();
                        return 0;
                    }
                    Console.WriteLine("Offline package creation failed.");
                }
                if (action == "C" || action == "")
                {
                    return 1;
                }
            }
        }

        private static int RunPowerShell(string root, bool offline, string output)
        {
            string script = ResolvePackagePath(root, "Invoke-CSACollector.ps1");
            StringBuilder arguments = new StringBuilder();
            arguments.Append("-NoLogo -NoProfile -NonInteractive ");
            arguments.Append("-ExecutionPolicy Bypass -File ");
            arguments.Append(Quote(script));
            if (offline)
            {
                arguments.Append(" -NoSubmit -ExportPath ");
                arguments.Append(Quote(output));
            }
            ProcessStartInfo start = new ProcessStartInfo(
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                arguments.ToString());
            start.WorkingDirectory = root;
            start.UseShellExecute = false;
            start.CreateNoWindow = false;
            using (Process process = Process.Start(start))
            {
                process.WaitForExit();
                return process.ExitCode;
            }
        }

        private static string ResolvePackagePath(string root, string relative)
        {
            if (Path.IsPathRooted(relative) ||
                relative.Replace('\\', '/').Split('/').Contains(".."))
            {
                throw new InvalidDataException("Trusted path is unsafe.");
            }
            string path = Path.GetFullPath(Path.Combine(
                root, relative.Replace('/', Path.DirectorySeparatorChar)));
            string prefix = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
            if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Trusted path escapes package root.");
            }
            return path;
        }

        private static byte[] ReadExactly(Stream stream, int length)
        {
            byte[] value = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int read = stream.Read(value, offset, length - offset);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                offset += read;
            }
            return value;
        }

        private static string Sha256File(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            using (SHA256 sha = SHA256.Create())
            {
                return "sha256:" + String.Concat(
                    sha.ComputeHash(stream).Select(value => value.ToString("x2")));
            }
        }

        private static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }
            int difference = 0;
            for (int index = 0; index < left.Length; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }

        private static bool RemoveTemporaryDirectory(string path)
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                try
                {
                    if (Directory.Exists(path))
                    {
                        Directory.Delete(path, true);
                    }
                    return !Directory.Exists(path);
                }
                catch (IOException)
                {
                    Thread.Sleep(200);
                }
                catch (UnauthorizedAccessException)
                {
                    Thread.Sleep(200);
                }
            }
            return !Directory.Exists(path);
        }

        private static string SafeServer(string value)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidDataException("Collector server identity is invalid.");
            }
            return uri.GetLeftPart(UriPartial.Authority);
        }

        private static string SafeMessage(Exception error)
        {
            string message = error.Message ?? "Unexpected Collector error.";
            return message.Replace("\r", " ").Replace("\n", " ");
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private static void WaitForUser()
        {
            if (!Console.IsInputRedirected)
            {
                Console.WriteLine();
                Console.WriteLine("Press Enter to close.");
                Console.ReadLine();
            }
        }
    }
}
