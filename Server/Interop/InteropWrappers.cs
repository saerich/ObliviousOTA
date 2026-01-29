using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ObliviousOTA.Interop;

internal class InteropWrappers
{
    internal static byte[]? OpaqueRegister(string username, byte[] alpha, byte[] seed)
    {
        if(File.Exists($"{username}.opqr")) { return null; } //Fully registered.
        if(File.Exists($"{username}.opqs")) { File.Delete($"{username}.opqs"); } //Registration was aborted mid-way.
        if(alpha.Length > Interop.crypto_core_ristretto255_BYTES) { return null; }

        byte[] rSec = new byte[Interop.OPAQUE_REGISTER_SECRET_LEN];
        byte[] rPub = new byte[Interop.OPAQUE_REGISTER_PUBLIC_LEN];
        int registerOutcome = Interop.OpaqueRegister(alpha, seed, rSec, rPub);

        if(registerOutcome == -1)
        {
            Console.WriteLine("Registration error.");
            CryptographicOperations.ZeroMemory(alpha); 
            CryptographicOperations.ZeroMemory(rSec); 
            CryptographicOperations.ZeroMemory(rPub); 
            return null; 
        }

        File.WriteAllBytes($"{username}.opqs", rSec);
        CryptographicOperations.ZeroMemory(rSec);
        return rPub;
    }

    internal static byte[]? OpaqueRegisterFinalize(string username, byte[] registerRecord)
    {
        if(!File.Exists($"{username}.opqs")) { return null; } //No registration started.
        byte[] rec = new byte[Interop.OPAQUE_USER_RECORD_LEN];
        Interop.OpaqueRegisterFinalize(File.ReadAllBytes($"{username}.opqs"), registerRecord, rec);
        File.WriteAllBytes($"{username}.opqr", rec);
        File.Delete($"{username}.opqs"); //Delete registration secret.
        return rec;
    }
}