using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Components.Web;
using ObliviousOTA.Interop;
using ObliviousOTA.Models.Request;

var b = WebApplication.CreateBuilder(args);

b.WebHost.ConfigureKestrel(x =>
{
    x.Limits.MinRequestBodyDataRate = null;
    x.Limits.KeepAliveTimeout = TimeSpan.FromHours(1); //Server is miles away atm, this should be lower.
    x.ListenAnyIP(5000, listen =>
    {
        //Remove this if running behind reverse proxy / TLS offloading, or provide certificate here.
        listen.UseHttps("./esp.pfx", Environment.GetEnvironmentVariable("BLIND_FETCH_TLS_PASSWORD"));
    });
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
if(!File.Exists("Logs/Executions.csv"))
{
    File.WriteAllText("Logs/Executions.csv", "Start Time,TTFB,TTLB,Blocks Served,SlotOrder,Aborted?,Aborted at\n");
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

byte[] oprfFileSeed = new byte[Interop.crypto_scalarmult_SCALARBYTES];

if(!File.Exists("oprffileseed"))
{
    int ret = Interop.OpaqueInit(oprfFileSeed);
    if(ret == 0) { File.WriteAllBytes("oprffileseed", oprfFileSeed); }
    else { throw new Exception("Could not create OPRF File Seed."); }
}
else
{
    oprfFileSeed = File.ReadAllBytes("oprffileseed");
}
byte[] oprfSizeSeed = new byte[Interop.crypto_scalarmult_SCALARBYTES];

if(!File.Exists("oprfsizeseed"))
{
    int ret = Interop.OpaqueInit(oprfSizeSeed);
    if(ret == 0) { File.WriteAllBytes("oprfsizeseed", oprfSizeSeed); }
    else { throw new Exception("Could not create OPRF Size Seed."); }
}
else
{
    oprfSizeSeed = File.ReadAllBytes("oprfsizeseed");
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

app.MapPost("/PlainOTA", async ctx =>
{
    if(!File.Exists("PlainExecutions.csv"))
    {
        File.WriteAllText("PlainExecutions.csv", "Date,TTFB,TTLB,Bytes\n");
    }
    DateTime start = DateTime.UtcNow;
    ctx.Response.ContentType = "application/octet-stream";
    ctx.Response.StatusCode = 200;
    using FileStream fs = new("PlainFirmware/firmware.bin", FileMode.Open, FileAccess.Read, FileShare.Read);
    ctx.Response.ContentLength = fs.Length;
    DateTime ttfb = DateTime.UtcNow;
    await fs.CopyToAsync(ctx.Response.Body);
    await ctx.Response.Body.FlushAsync();
    
    ctx.Response.OnCompleted(() =>
    {
        File.AppendAllLines("PlainExecutions.csv", [$"{start},{ttfb},{DateTime.UtcNow - start},{ctx.Response.ContentLength}"]);
        return Task.CompletedTask;
    });
});

app.MapPost("/GenerateHeaders", async ctx =>
{
    byte[] alpha1 = new byte[32];
    byte[] alpha2 = new byte[32];
    byte[] unameLen = new byte[4];

    await ctx.Request.Body.ReadExactlyAsync(alpha1);
    await ctx.Request.Body.ReadExactlyAsync(alpha2);
    await ctx.Request.Body.ReadExactlyAsync(unameLen);

    byte[] unameBuf = new byte[BitConverter.ToInt32(unameLen)];
    await ctx.Request.Body.ReadExactlyAsync(unameBuf);


    byte[]? beta1 = InteropWrappers.SelectOPRFEvaluate(alpha1, oprfFileSeed);
    byte[]? beta2 = InteropWrappers.SelectOPRFEvaluate(alpha2, oprfSizeSeed);
    byte[]? userKey = null;
    string username = Encoding.UTF8.GetString(unameBuf);

    try
    {
        userKey = File.ReadAllBytes($"{username}.osk");
        File.Delete($"{username}.osk");
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
    ctx.Response.ContentLength = 68L + (firmwareCount * 36L) + (firmwareCount * 4096L * 1052L); 

    using MemoryStream headerMs = new();
    headerMs.Write(beta1);
    headerMs.Write(beta2);
    
    #if !ORDERED
    for (int i = (int)firmwareCount - 1; i > 0; i--)
    {
        int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
        (allFirmwareKeys[i], allFirmwareKeys[j]) = (allFirmwareKeys[j], allFirmwareKeys[i]);
    }
    #endif

    headerMs.Write(BitConverter.GetBytes((int)firmwareCount));
    IEnumerable<string> keyBlock = [];
    
    foreach(var key in allFirmwareKeys) 
    {
        byte[]? fwHash = InteropWrappers.CreateKeyFromSKUKey(userKey, File.ReadAllBytes(key));
        headerMs.Write(fwHash ?? new byte[64]);
        long actualFileSize = new FileInfo($"Firmware/{Path.GetFileNameWithoutExtension(key)}.bin").Length;
        (byte[] Ciphertext, byte[] Nonce)? len = InteropWrappers.EncryptFirmwareSize(userKey, oprfSizeSeed, fwHash ?? new byte[64], BitConverter.GetBytes(actualFileSize)); //24 bytes.
        if(len == null) 
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden; 
            return; 
        }
        headerMs.Write(len.Value.Nonce);
        headerMs.Write(len.Value.Ciphertext);
        keyBlock = keyBlock.Append($"[{Convert.ToHexString(fwHash)}|{actualFileSize}|{Convert.ToHexString(len.Value.Nonce)}|{Convert.ToHexString(len.Value.Ciphertext)}]");
    }
    byte[] header = headerMs.ToArray();
    await ctx.Response.Body.WriteAsync(header);
    await File.AppendAllTextAsync("Header.csv", $"{DateTime.UtcNow},{Convert.ToHexString(beta1)},{Convert.ToHexString(beta2)},{ctx.Response.ContentLength},{firmwareCount},{string.Join("||", keyBlock)}\n");
});

app.MapGet("/GeneratePlainMetadata", async ctx =>
{
    for(int lp = 0; lp < 100; lp++)
    {
        string[] allFirmwareKeys = Directory.GetFiles("Keys");
        long firmwareCount = allFirmwareKeys.Length;
        #if !ORDERED
        for (int i = (int)firmwareCount - 1; i > 0; i--)
        {
            int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
            (allFirmwareKeys[i], allFirmwareKeys[j]) = (allFirmwareKeys[j], allFirmwareKeys[i]);
        }
        #endif
        
        IEnumerable<string> keyBlock = [];
        foreach(var key in allFirmwareKeys) 
        {
            long actualFileSize = new FileInfo($"Firmware/{Path.GetFileNameWithoutExtension(key)}.bin").Length;
            keyBlock = keyBlock.Append($"[{key}||{actualFileSize}]");
        }
        await File.AppendAllTextAsync("PlainHeader.csv", $"{DateTime.UtcNow},{ctx.Response.ContentLength},{firmwareCount},{string.Join("||", keyBlock)}\n");
    }
    ctx.Response.StatusCode = 200;
});


app.MapPost("/Download", async ctx =>
{
    DateTime startTime = DateTime.UtcNow;
    DateTime? aborted = null;
    int blocksServed = 0;
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

    byte[]? beta1 = InteropWrappers.SelectOPRFEvaluate(alpha1, oprfFileSeed);
    byte[]? beta2 = InteropWrappers.SelectOPRFEvaluate(alpha2, oprfSizeSeed);
    byte[]? userKey = null;


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
    ctx.Response.ContentLength = 68L + (firmwareCount * 36L) + (firmwareCount * 4096L * 1052L); //36L = size header size, 4096L = blocks, 1025L = blockSize, 68L = beta 1, 2 and number of firmware.
    
    // ctx.Response.Headers.TransferEncoding = "identity";
    using MemoryStream headerMs = new();
    headerMs.Write(beta1);
    headerMs.Write(beta2);
    
    #if !ORDERED
    for (int i = (int)firmwareCount - 1; i > 0; i--)
    {
        int j = System.Security.Cryptography.RandomNumberGenerator.GetInt32(i + 1);
        (allFirmwareKeys[i], allFirmwareKeys[j]) = (allFirmwareKeys[j], allFirmwareKeys[i]);
    }
    #endif

    headerMs.Write(BitConverter.GetBytes((int)firmwareCount));
    
    foreach(var key in allFirmwareKeys) 
    {
        byte[]? fwHash = InteropWrappers.CreateKeyFromSKUKey(userKey, File.ReadAllBytes(key));
        // headerMs.Write(fwHash ?? new byte[64]);
        long actualFileSize = new FileInfo($"Firmware/{Path.GetFileNameWithoutExtension(key)}.bin").Length;
        (byte[] Ciphertext, byte[] Nonce)? len = InteropWrappers.EncryptFirmwareSize(userKey, oprfSizeSeed, fwHash ?? new byte[64], BitConverter.GetBytes(actualFileSize)); //24 bytes.
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

            (byte[] Ciphertext, byte[] Nonce)? encryptedFirmware = InteropWrappers.EncryptFirmware(x.idx, block++, userKey, oprfFileSeed, deviceKey, plainText);
            if(encryptedFirmware == null) { Console.WriteLine("Null response."); break; }

            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Nonce);
            await ctx.Response.Body.WriteAsync(encryptedFirmware.Value.Ciphertext);
            if(aborted == null) { blocksServed++; }
            remaining -= plainText.Length;
        }
        
        fs.Close();
    }
    await ctx.Response.Body.FlushAsync();
    DateTime ttlb = DateTime.UtcNow;
    Console.WriteLine("Downloaded some firmware.");
    File.AppendAllText($"Logs/Executions.csv", $"{startTime},{ttfb - startTime},{ttlb - startTime},{blocksServed},[{string.Join("|", allFirmwareKeys.Select(x => $"{x.Replace("Keys/", "").Replace(".k", "")}" ))}],{aborted != null},{(aborted == null ? "" : aborted - startTime)}\n");
});
app.Run();
