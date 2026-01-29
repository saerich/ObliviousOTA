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

app.MapGet("/Login", () =>
{

});

app.MapGet("/LoginFinalize", () =>
{

});

app.Run();
