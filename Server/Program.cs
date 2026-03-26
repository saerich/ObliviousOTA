using System.Text;
using ObliviousOTA.Interop;
using ObliviousOTA.Models.Request;

var b = WebApplication.CreateBuilder(args);

b.WebHost.ConfigureKestrel(x =>
{
    x.Limits.MinRequestBodyDataRate = null;
    x.Limits.KeepAliveTimeout = TimeSpan.FromHours(1); //Server is miles away atm, this should be lower.
});

var app = b.Build();

var cleanup = () =>
{
    _ = Directory.GetFiles(".", "*.osk").Select(x => { File.Delete(x); return 0; }).ToArray(); //Ensure all users are logged out when server stopped.
    _ = Directory.GetFiles(".", "*.olau0").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all pending login attempts.
    _ = Directory.GetFiles(".", "*.olsk").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all potential shared keys.
    _ = Directory.GetFiles(".", "*.opqs").Select(x => { File.Delete(x); return 0; }).ToArray(); //Terminate all registration in progress attempts.
};

cleanup();
app.Lifetime.ApplicationStopping.Register(cleanup);

Directory.CreateDirectory("Logs");
if(!File.Exists("Logs/Executions.log"))
{
    File.WriteAllText("Logs/Executions.log", "Start Time,TTFB,TTLB,Aborted?,Aborted at\n");
}

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

app.MapGet("/KTV", async([AsParameters] KTVRequest req) =>
{
    File.AppendAllText("Logs/KTV.csv", $"{DateTime.UtcNow},{req.Username},{req.Alpha1},{req.Alpha2},{req.Beta1},{req.Beta2},{req.N1},{req.N2},{req.RWDU1},{req.RWDU2},{req.FWHash},{req.DeviceKey},{req.RealBlocks},{req.AbsorbedBlocks},{req.SK}\n");
});

app.MapGet("/ClientLog", async([AsParameters] LogRequest req) =>
{
    
});

app.MapPost("/Download", async ctx =>
{
    DateTime startTime = DateTime.UtcNow;
    DateTime? aborted = null;
    using var reg = ctx.RequestAborted.Register(() =>
    {
        aborted = DateTime.UtcNow;
        Console.WriteLine("Client terminated early.");    
    });
    
    byte[] alpha1 = new byte[32];
    byte[] alpha2 = new byte[32];
    byte[] unameLen = new byte[4];
    
    await ctx.Request.Body.ReadExactlyAsync(alpha1);
    await ctx.Request.Body.ReadExactlyAsync(alpha2);
    await ctx.Request.Body.ReadExactlyAsync(unameLen);

    byte[] unameBuf = new byte[BitConverter.ToInt32(unameLen)];
    await ctx.Request.Body.ReadExactlyAsync(unameBuf);
    

    byte[]? beta1 = InteropWrappers.SelectOPRFEvaluate(alpha1);
    byte[]? beta2 = InteropWrappers.SelectOPRFEvaluate(alpha2);
    byte[]? userKey = null;


    //using StreamReader reader = new(ctx.Request.Body, System.Text.Encoding.UTF8);
    string username = Encoding.UTF8.GetString(unameBuf);
    
    try
    {
        userKey = File.ReadAllBytes($"{username}.osk");
        File.Delete($"{username}.osk"); //Log the user out, one use per key.
    }
    catch(Exception ex)
    {
        Console.WriteLine(ex);
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;        
    }

    string[] allFirmwareKeys = Directory.GetFiles("Keys");
    long firmwareCount = allFirmwareKeys.Length;

    ctx.Response.ContentType = "application/octet-stream";
    ctx.Response.StatusCode = 200;
    ctx.Response.ContentLength = 68L + (firmwareCount * 100L) + (firmwareCount * 4096L * 1052L); //100L = size header size, 4096L = blocks, 1025L = blockSize, 72L = beta 1, 2 and number of firmware.
    
    // ctx.Response.Headers.TransferEncoding = "identity";
    using MemoryStream headerMs = new();
    headerMs.Write(beta1);
    headerMs.Write(beta2);

    for (int i = (int)firmwareCount - 1; i > 0; i--)
    {
        int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
        (allFirmwareKeys[i], allFirmwareKeys[j]) = (allFirmwareKeys[j], allFirmwareKeys[i]);
    }

    headerMs.Write(BitConverter.GetBytes((int)firmwareCount));
    
    foreach(var key in allFirmwareKeys) 
    {
        byte[]? fwHash = InteropWrappers.CreateKeyFromSKUKey(userKey, File.ReadAllBytes(key));
        headerMs.Write(fwHash ?? new byte[64]);
        long actualFileSize = new FileInfo($"Firmware/{Path.GetFileNameWithoutExtension(key)}.bin").Length;
        (byte[] Ciphertext, byte[] Nonce)? len = InteropWrappers.EncryptFirmwareSize(userKey, seed, fwHash ?? new byte[64], BitConverter.GetBytes(actualFileSize)); //24 bytes.
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
    DateTime ttfb = DateTime.UtcNow;
    byte[] slots = [];
    const int slotSize = 4_194_304; // 4,194,304

    foreach(var x in allFirmwareKeys.Select((key, idx) => (key, idx)))
    {
        await using var fs = File.OpenRead($"Firmware/{Path.GetFileNameWithoutExtension(x.key)}.bin");
        if(fs.Length > slotSize) { fs.Close(); throw new InvalidOperationException("Only files up to 4MB are supported."); }

        long remaining = slotSize;
        byte[] plainText = new byte[1024];
        int block = 0;
        while(remaining > 0)
        {
            int read = await fs.ReadAsync(plainText, 0, (int)Math.Min(1024, remaining));
            if(read == 0) { Array.Clear(plainText, 0, plainText.Length); }
            else if(read < plainText.Length) { Array.Clear(plainText, read, plainText.Length - read); }

            byte[] deviceKey = File.ReadAllBytes(x.key);

            (byte[] Ciphertext, byte[] Nonce)? encryptedFirmware = InteropWrappers.EncryptFirmware(x.idx, block++, userKey, seed, deviceKey, plainText);
            if(encryptedFirmware == null) { Console.WriteLine("Null response."); break; }

            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Nonce);
            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Ciphertext);

            remaining -= plainText.Length;
        }
        
        fs.Close();
    }
    await ctx.Response.Body.FlushAsync();
    DateTime ttlb = DateTime.UtcNow;
    Console.WriteLine("Downloaded some firmware.");
    File.AppendAllText($"Logs/Executions.log", $"{startTime},{ttfb - startTime},{ttlb - startTime},{aborted == null},{(aborted == null ? "" : aborted - startTime)}\n");
});
app.Run();
