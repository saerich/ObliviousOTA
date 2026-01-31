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

app.Run();
