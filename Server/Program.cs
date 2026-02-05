using Microsoft.AspNetCore.Mvc;
using ObliviousOTA.Interop;
using ObliviousOTA.Models.Request;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(x => 
{
    x.ListenAnyIP(5234);
});


var app = builder.Build();

var cleanup = () =>
{
    _ = Directory.GetFiles(".", "*.osk").Select(x => { File.Delete(x); return 0; }).ToArray(); //Ensure all users are logged out when server stopped.
    _ = Directory.GetFiles(".", "*.olau0").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all pending login attempts.
    _ = Directory.GetFiles(".", "*.olsk").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all potential shared keys.
    _ = Directory.GetFiles(".", "*.opqs").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all registration in progress attempts.
};

cleanup();
app.Lifetime.ApplicationStopping.Register(cleanup);

byte[] seed = new byte[Interop.crypto_scalarmult_SCALARBYTES];

if(!File.Exists("opaqueseed"))
{
    int ret = Interop.OpaqueInit(seed);
    if(ret == 0) { File.WriteAllBytes("opaqueseed", seed); }
    else { throw new Exception("Could not create OPAQUE Seed."); }
}
else
{
    seed = File.ReadAllBytes("opaqueseed");
}

app.MapGet("/Register", ([AsParameters] RegisterRequest req) =>
{
    if(File.Exists($"{req.Username}.opqr")) { return Results.Conflict("Device registration not possible."); }
    byte[] rawAlpha = Convert.FromHexString(req.Alpha);
    byte[]? rPub = InteropWrappers.OpaqueRegister(req.Username, rawAlpha, seed);
    Console.WriteLine(Convert.ToHexString(rPub ?? []));
    if(rPub == null) { return Results.BadRequest("Could not register device."); }
    return Results.Ok(Convert.ToHexString(rPub));
});

app.MapGet("/RegisterFinalize", ([AsParameters] RegisterFinalizeRequest req) =>
{
    byte[] rawRegRec = Convert.FromHexString(req.RegisterRecord);
    byte[]? rec = InteropWrappers.OpaqueRegisterFinalize(req.Username, rawRegRec);
    Console.WriteLine(Convert.ToHexString(rec ?? []));
    if(rec == null) { return Results.BadRequest("Could not finalize device registration."); }
    return Results.Ok();
    
});

app.MapGet("/Login", ([AsParameters] LoginRequest req) =>
{
    byte[] rawKe1 = Convert.FromHexString(req.Ke1);
    byte[]? res = InteropWrappers.OpaqueLogin(rawKe1, req.Username);
    if(res == null) { return Results.BadRequest("Could not attempt to log in."); }
    return Results.Ok(Convert.ToHexString(res));
});

app.MapGet("/LoginVerify", ([AsParameters] LoginVerifyRequest req) =>
{
    byte[] rawAuthU = Convert.FromHexString(req.AuthU);
    if(!InteropWrappers.OpaqueLoginVerify(rawAuthU, req.Username)) { return Results.BadRequest("Could not log user in."); }
    return Results.Ok();     
});

app.MapGet("/Download", async (HttpContext ctx, [AsParameters] DownloadRequest req) =>
{
    byte[] alpha1 = Convert.FromHexString(req.Alpha1);
    byte[] alpha2 = Convert.FromHexString(req.Alpha2);
    byte[]? beta1 = InteropWrappers.SelectOPRFEvaluate(alpha1);
    byte[]? beta2 = InteropWrappers.SelectOPRFEvaluate(alpha2);
    
    byte[] userKey = File.ReadAllBytes($"{req.Username}.osk");
    File.Delete($"{req.Username}"); //Log the user out, one use per key.

    if(beta1 == null || beta2 == null) 
    { 
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    ctx.Response.ContentType = "application/octet-stream";
    ctx.Response.StatusCode = 200;
    ctx.Response.Headers.TransferEncoding = "identity";
    using MemoryStream headerMs = new();
    headerMs.Write(beta1);
    headerMs.Write(beta2);
    string[] allFirmwareKeys = Directory.GetFiles("Keys");
    headerMs.Write(BitConverter.GetBytes(allFirmwareKeys.Length));
    
    foreach(var key in allFirmwareKeys) 
    {
        byte[]? fwHash = InteropWrappers.CreateKeyFromSKUKey(userKey, File.ReadAllBytes(key));
        headerMs.Write(fwHash ?? new byte[64]);
        long actualFileSize = new FileInfo($"Firmware/{Path.GetFileNameWithoutExtension(key)}.bin").Length;
        (byte[] Ciphertext, byte[] Nonce)? len = InteropWrappers.EncryptFirmwareSize(userKey, seed, fwHash ?? new byte[64], BitConverter.GetBytes(actualFileSize));
        if(len == null) 
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden; 
            return; 
        }
        headerMs.Write(len.Value.Nonce);
        headerMs.Write(len.Value.Ciphertext);
    }
    byte[] header = headerMs.ToArray();
    await ctx.Response.Body.WriteAsync(header);
    byte[] slots = [];
    const int slotSize = 4_194_304; // 4,194,304

    foreach(var x in allFirmwareKeys.Select((key, idx) => (key, idx)))
    {
        await using var fs = File.OpenRead($"Firmware/{Path.GetFileNameWithoutExtension(x.key)}.bin");
        if(fs.Length > slotSize) { fs.Close(); throw new InvalidOperationException("Only files up to 4MB are supported."); }

        long remaining = slotSize;
        byte[] plainText = new byte[1024];

        while(remaining > 0)
        {
            int read = await fs.ReadAsync(plainText, 0, (int)Math.Min(1024, remaining));
            if(read == 0) { Array.Clear(plainText, 0, plainText.Length); }
            else if(read < plainText.Length) { Array.Clear(plainText, read, plainText.Length - read); }

            byte[] deviceKey = File.ReadAllBytes(x.key);

            (byte[] Ciphertext, byte[] Nonce)? encryptedFirmware = InteropWrappers.EncryptFirmware(userKey, seed, deviceKey, plainText);
            if(encryptedFirmware == null) { Console.WriteLine("Null response."); break; }

            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Nonce);
            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Ciphertext);

            remaining -= plainText.Length;
        }
        
        fs.Close();
    }
    await ctx.Response.Body.FlushAsync();
    Console.WriteLine("Downloaded some firmware.");
});

app.Run();
