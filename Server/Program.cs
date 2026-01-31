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

app.Lifetime.ApplicationStopping.Register(() =>
{
    File.Delete("*.osk"); //Ensure all users are logged out when server stopped.
    File.Delete("*.olau0"); //Terminate all pending login attempts.
    File.Delete("*.olsk"); //Terminate all potential shared keys.
    File.Delete("*.opqs"); //Terminate all registration in progress attempts.
});

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
    Console.WriteLine(req.Alpha);
    byte[] rawAlpha = Convert.FromHexString(req.Alpha);
    byte[]? rPub = InteropWrappers.OpaqueRegister(req.Username, rawAlpha, seed);
    Console.WriteLine(Convert.ToHexString(rPub ?? []));
    if(rPub == null) { return Results.BadRequest("Could not register device."); }
    return Results.Ok(Convert.ToHexString(rPub));
});

app.MapGet("/RegisterFinalize", ([AsParameters] RegisterFinalizeRequest req) =>
{
    Console.WriteLine(req.RegisterRecord);
    byte[] rawRegRec = Convert.FromHexString(req.RegisterRecord);
    byte[]? rec = InteropWrappers.OpaqueRegisterFinalize(req.Username, rawRegRec);
    Console.WriteLine(Convert.ToHexString(rec ?? []));
    if(rec == null) { return Results.BadRequest("Could not finalize device registration."); }
    return Results.Ok();
    
});

app.MapGet("/Login", ([AsParameters] LoginRequest req) =>
{
    Console.WriteLine(req.Ke1);
    byte[] rawKe1 = Convert.FromHexString(req.Ke1);
    byte[]? res = InteropWrappers.OpaqueLogin(rawKe1, req.Username);
    if(res == null) { return Results.BadRequest("Could not attempt to log in."); }
    return Results.Ok(Convert.ToHexString(res));
});

app.MapGet("/LoginVerify", ([AsParameters] LoginVerifyRequest req) =>
{
    Console.WriteLine(req.AuthU);
    byte[] rawAuthU = Convert.FromHexString(req.AuthU);
    if(!InteropWrappers.OpaqueLoginVerify(rawAuthU, req.Username)) { return Results.BadRequest("Could not log user in."); }
    return Results.Ok();     
});

app.Run();
