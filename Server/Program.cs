using ObliviousOTA.Interop;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

OPAQUE.HelloWorld(out IntPtr str, out int strLen);
Console.WriteLine(strLen);

app.MapPost("/Register", (string alpha) =>
{
    Console.WriteLine(alpha);
    return "";
});

app.MapGet("/RegisterFinalize", () =>
{
    
    return "";
});

app.MapGet("/Login", () =>
{

});

app.MapGet("/LoginFinalize", () =>
{

});

app.Run();
