// Exercise the production bootstrapper methods without collecting endpoint data
// or depending on the CI runner's elevation level.
using System;
using System.IO;
using System.Reflection;
using CSA.Collector;

internal static class BootstrapHarness
{
    private static int Main(string[] args)
    {
        try
        {
            const BindingFlags flags = BindingFlags.Static | BindingFlags.NonPublic;
            if (args[0] == "extract")
                typeof(Program).GetMethod("ExtractAndVerifyPackage", flags).Invoke(null,
                    new object[] { args[1], args[2] });
            else
            {
                Func<string> read = () => File.ReadAllText(args[1]);
                var method = typeof(Program).GetMethod("RetryFileOperation", flags)
                    .MakeGenericMethod(typeof(string));
                Console.WriteLine(method.Invoke(null, new object[] { read }));
            }
            return 0;
        }
        catch (TargetInvocationException error)
        {
            Console.Error.WriteLine(error.InnerException.GetType().Name + ": " + error.InnerException.Message);
            return 1;
        }
    }
}
