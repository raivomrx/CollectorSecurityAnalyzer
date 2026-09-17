Set-StrictMode -Version 2.0

function Get-CSARegisteredAntivirusProducts {
    if (-not ('CSA.SecurityCenterAntivirus' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CSA {
    public sealed class AntivirusProduct {
        public string Name { get; set; }
        public string State { get; set; }
        public string SignatureStatus { get; set; }
    }

    public static class SecurityCenterAntivirus {
        [DllImport("ole32.dll", ExactSpelling = true)]
        private static extern int CoCreateInstance(
            ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr instance);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int InitializeMethod(IntPtr self, uint provider);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int CountMethod(IntPtr self, out int count);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int ItemMethod(IntPtr self, uint index, out IntPtr product);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int NameMethod(IntPtr self, out IntPtr name);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate int StateMethod(IntPtr self, out int state);

        private static T Method<T>(IntPtr instance, int slot) where T : class {
            IntPtr table = Marshal.ReadIntPtr(instance);
            return (T)(object)Marshal.GetDelegateForFunctionPointer(
                Marshal.ReadIntPtr(table, slot * IntPtr.Size), typeof(T));
        }

        private static string StateName(int value) {
            switch (value) {
                case 0: return "ON";
                case 1: return "OFF";
                case 2: return "SNOOZED";
                case 3: return "EXPIRED";
                default: return "UNKNOWN";
            }
        }

        private static string SignatureName(int value) {
            switch (value) {
                case 0: return "UP_TO_DATE";
                case 1: return "OUT_OF_DATE";
                default: return "UNKNOWN";
            }
        }

        public static AntivirusProduct[] GetProducts() {
            Guid clsid = new Guid("17072f7b-9abe-4a74-a261-1eb76b55107a");
            Guid iid = new Guid("722a338c-6e8e-4e72-ac27-1417fb0c81c2");
            IntPtr list;
            Marshal.ThrowExceptionForHR(CoCreateInstance(
                ref clsid, IntPtr.Zero, 1, ref iid, out list));
            try {
                Marshal.ThrowExceptionForHR(Method<InitializeMethod>(list, 7)(list, 4));
                int count;
                Marshal.ThrowExceptionForHR(Method<CountMethod>(list, 8)(list, out count));
                var products = new List<AntivirusProduct>();
                for (uint index = 0; index < count; index++) {
                    IntPtr product;
                    Marshal.ThrowExceptionForHR(Method<ItemMethod>(list, 9)(list, index, out product));
                    try {
                        IntPtr name;
                        Marshal.ThrowExceptionForHR(Method<NameMethod>(product, 7)(product, out name));
                        string productName;
                        try { productName = Marshal.PtrToStringBSTR(name); }
                        finally { Marshal.FreeBSTR(name); }
                        int state;
                        int signature;
                        Marshal.ThrowExceptionForHR(Method<StateMethod>(product, 8)(product, out state));
                        Marshal.ThrowExceptionForHR(Method<StateMethod>(product, 9)(product, out signature));
                        products.Add(new AntivirusProduct {
                            Name = productName,
                            State = StateName(state),
                            SignatureStatus = SignatureName(signature)
                        });
                    }
                    finally { Marshal.Release(product); }
                }
                return products.ToArray();
            }
            finally { Marshal.Release(list); }
        }
    }
}
'@
    }

    [CSA.SecurityCenterAntivirus]::GetProducts() | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            state = [string]$_.State
            signatureStatus = [string]$_.SignatureStatus
        }
    }
}

Export-ModuleMember -Function Get-CSARegisteredAntivirusProducts
