// Per-session private delivery container. The immutable inner Collector performs
// the existing ADR 5682 verification; this executable is not a new trust root.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;

namespace CSA.Collector
{
    internal static class BoundEntry
    {
        private static int Main(string[] args) { return Program.RunBoundPilot(args); }
    }
    internal static partial class Program
    {
        internal static int RunBoundPilot(string[] args)
        {
            string root = null;
            int code = 1;
            try
            {
                if (args.Length > 1 || args.Length == 1 && args[0] != "--quick-run")
                    throw new InvalidDataException("CSA-PILOT-ARGUMENTS");
                RejectElevatedProcess();
                Console.Title = "CSA Security Assessment";
                Console.WriteLine("CSA phase: VERIFY / private assessor-approved Collector");
                using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("CSA.Pilot"))
                using (MemoryStream memory = new MemoryStream())
                {
                    if (resource == null || resource.Length > 64 * 1024 * 1024)
                        throw new InvalidDataException("CSA-PILOT-CONTAINER");
                    resource.CopyTo(memory);
                    byte[] payload = memory.ToArray();
                    using (SHA256 hash = SHA256.Create())
                        if (BitConverter.ToString(hash.ComputeHash(payload)).Replace("-", "").ToLowerInvariant() != BoundPins.Payload)
                            throw new InvalidDataException("CSA-PILOT-CONTAINER-HASH");
                    root = CreateRestrictedTemporaryDirectory();
                    HashSet<string> expected = new HashSet<string>(new[] { "pilot-approval.json", "publisher-manifest.json",
                        "publisher-manifest.p7s", "session-envelope.json", "session-envelope.p7s", "collector.zip",
                        "CSA-TrustedCollector.exe", "Start-CSATrustedCollector.ps1" }, StringComparer.Ordinal);
                    using (MemoryStream input = new MemoryStream(payload, false))
                    using (ZipArchive archive = new ZipArchive(input, ZipArchiveMode.Read))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            if (!expected.Remove(entry.FullName) || entry.Length < 0 || entry.Length > 64 * 1024 * 1024)
                                throw new InvalidDataException("CSA-PILOT-CONTAINER-PATH");
                            using (Stream source = entry.Open())
                            using (FileStream target = RetryFileOperation(() => new FileStream(Path.Combine(root, entry.FullName),
                                FileMode.CreateNew, FileAccess.Write, FileShare.None))) source.CopyTo(target);
                        }
                        if (expected.Count != 0) throw new InvalidDataException("CSA-PILOT-CONTAINER-MISSING");
                    }
                }
                string executable = Path.Combine(root, "CSA-TrustedCollector.exe");
                using (FileStream lease = RetryFileOperation(() => new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read)))
                {
                    using (SHA256 hash = SHA256.Create())
                        if (BitConverter.ToString(hash.ComputeHash(lease)).Replace("-", "").ToLowerInvariant() != BoundPins.Executable)
                            throw new InvalidDataException("CSA-PILOT-EXE-HASH");
                    ProcessStartInfo start = new ProcessStartInfo(executable, "--assessor-pilot --bundle " + Quote(root)
                        + " --approval-sha256 sha256:" + BoundPins.Approval + (args.Length == 1 ? " --quick-run" : ""));
                    start.UseShellExecute = false;
                    using (Process child = Process.Start(start)) { child.WaitForExit(); code = child.ExitCode; }
                }
            }
            catch (TransientFileLockException) { Console.Error.WriteLine("CSA-COL-FILELOCK: Endpoint security is scanning a Collector file. Retry shortly."); }
            catch (InvalidOperationException) { Console.Error.WriteLine("CSA-PILOT-STANDARD-USER-REQUIRED: Run normally without administrator rights."); }
            catch { Console.Error.WriteLine("CSA-PILOT-START-FAILED: Collector verification or Windows policy stopped execution. Contact the assessor."); }
            finally
            {
                if (root != null && !RemoveTemporaryDirectory(root)) { code = 1; Console.Error.WriteLine("CSA-BOOT-CLEANUP: Temporary files remain; contact the assessor."); }
            }
            if (code != 0) WaitForUser();
            return code;
        }
    }
}
