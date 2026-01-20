using System.Runtime.InteropServices;

namespace ObliviousOTA.Interop;

internal static partial class OPAQUE
{
    private const string Library = "OpaqueInterop";
    
    [LibraryImport(Library, EntryPoint = "HelloWorld")]
    internal static partial int HelloWorld(out IntPtr outStr, out int strLen);

    // [LibraryImport(Library, EntryPoint = "OpaqueRegister")]
    // internal static partial int OpaqueRegister();

    // [LibraryImport(Library, EntryPoint = "OpaqueRegisterFinalize")]
    // internal static partial int OpaqueRegister();
}