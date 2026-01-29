using System.Runtime.InteropServices;

namespace ObliviousOTA.Interop;

internal static partial class Interop
{
    private const string Library = "libInterop";
    internal const int crypto_core_ristretto255_BYTES = 32;
    internal const int OPAQUE_REGISTER_PUBLIC_LEN = 64;
    internal const int OPAQUE_REGISTER_SECRET_LEN = 64;
    internal const int crypto_scalarmult_SCALARBYTES = 32;
    internal const int OPAQUE_USER_RECORD_LEN = 256;

    [LibraryImport(Library, EntryPoint = "OpaqueInit")]
    internal static partial int OpaqueInit([Out] byte[] Secret);

    [LibraryImport(Library, EntryPoint = "OpaqueRegister")]
    internal static partial int OpaqueRegister([In] byte[] alpha, [In] byte[] seed, [Out] byte[] rSec, [Out] byte[] rPub);

    [LibraryImport(Library, EntryPoint = "OpaqueRegisterFinalize")]
    internal static partial int OpaqueRegisterFinalize([In] byte[] rSec, [In] byte[] registerRecord, [Out] byte[] serverRecord);
}