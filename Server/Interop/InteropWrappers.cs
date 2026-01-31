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

    internal static byte[]? OpaqueLogin(byte[] ke1, string username)
    {
        if(!File.Exists($"{username}.opqr")) { return null; } //Not registered.
        if(File.Exists($"{username}.olau0")) { File.Delete($"{username}.olau0"); } //Trying second login attempt, terminate first.
        byte[] rec = File.ReadAllBytes($"{username}.opqr");
        byte[] authU0 = new byte[Interop.crypto_auth_hmacsha512_BYTES];
        byte[] sk = new byte[Interop.OPAQUE_SHARED_SECRETBYTES];
        byte[] ke2 = new byte[Interop.OPAQUE_SERVER_SESSION_LEN];

        Interop.OpaqueLogin(ke1, rec, System.Text.Encoding.UTF8.GetBytes(username), authU0, sk, ke2);

        File.WriteAllBytes($"{username}.olau0", authU0);
        File.WriteAllBytes($"{username}.olsk", sk);

        return ke2;
    }

    internal static bool OpaqueLoginVerify(byte[] authU, string username)
    {
        if(!File.Exists($"{username}.olau0") || !File.Exists($"{username}.olsk")) { return false; }
        byte[] authU0 = File.ReadAllBytes($"{username}.olau0");
        File.Delete($"{username}.olau0");
        bool valid = Interop.OpaqueLoginVerify(authU0, authU) == 0;

        if(!valid) { File.Delete($"{username}.olsk"); } //Invalid login, delete calculated shared key.
        else { File.Move($"{username}.olsk", $"{username}.osk"); }
        return valid;
    }
}