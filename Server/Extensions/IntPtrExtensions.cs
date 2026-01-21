using System.Runtime.InteropServices;

namespace ObliviousOTA.Interop;
public static class IntPtrExtensions
{
    public static byte[] ToByteArray(this IntPtr pointer, int len)
    {
        if(pointer == IntPtr.Zero || len <= 0) { return []; }

        byte[] ret = new byte[len];
        Marshal.Copy(pointer, ret, 0, len);
        return ret;
    }

    public static string ToString(this IntPtr pointer, int len)
    {
        byte[] toStr = pointer.ToByteArray(len);
        return System.Text.Encoding.UTF8.GetString(toStr);
    }
}