using SyncApp;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory, WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot") });
builder.WebHost.UseUrls("http://127.0.0.1:" + (Environment.GetEnvironmentVariable("SYNCAPP_PORT") ?? "5055"));
builder.Services.AddSingleton<Registry>();
builder.Services.AddSingleton<GitService>();
builder.Services.AddSingleton<CryptoService>();
builder.Services.AddSingleton<SyncEngine>();
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
var app = builder.Build();
var csrf = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
var port = int.Parse(Environment.GetEnvironmentVariable("SYNCAPP_PORT") ?? "5055");
app.Use(async (ctx, next) =>
{
    if (!IPAddress.IsLoopback(ctx.Connection.RemoteIpAddress ?? IPAddress.None)) { ctx.Response.StatusCode = 403; return; }
    if (ctx.Request.Host.Port != port || ctx.Request.Host.Host is not ("localhost" or "127.0.0.1")) { ctx.Response.StatusCode = 403; return; }
    var expectedOrigin = $"{ctx.Request.Scheme}://{ctx.Request.Host}";
    if (ctx.Request.Headers.Origin.Count > 0 && ctx.Request.Headers.Origin != expectedOrigin) { ctx.Response.StatusCode = 403; return; }
    if (ctx.Request.Headers["Sec-Fetch-Site"] == "cross-site") { ctx.Response.StatusCode = 403; return; }
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.Headers.CacheControl = "no-store";
    ctx.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
    if (ctx.Request.Method is not ("GET" or "HEAD" or "OPTIONS"))
    {
        if (ctx.Request.Headers["X-SyncApp-CSRF"] != csrf) { ctx.Response.StatusCode = 403; return; }
    }
    try { await next(); }
    catch (Exception ex)
    {
        ctx.Response.StatusCode = ex is BadHttpRequestException badRequest ? badRequest.StatusCode
            : ex is KeyNotFoundException or FileNotFoundException ? 404 : ex is ArgumentException or InvalidDataException or InvalidOperationException or NotSupportedException or System.Security.Cryptography.CryptographicException ? 400 : 500;
        await ctx.Response.WriteAsJsonAsync(new { error = ex.Message });
    }
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/api/session", async (Registry registry) => new { csrf, projects = await registry.All() });
app.MapGet("/api/projects/{id}", async (string id, Registry registry) => await registry.Get(id));
app.MapPost("/api/projects/personal", async (CreateProject request, SyncEngine engine) =>
{
    var p = await engine.CreatePersonal(request.Folder, request.JunkPath, request.RepoPath, request.Passphrase);
    return Results.Json(new { project = p, personalFingerprint = CryptoService.PairFingerprint(p.PersonalSigningKey, p.PersonalRecipient) });
});
app.MapPost("/api/projects/work", async (CreateProject request, SyncEngine engine) =>
{
    var p = await engine.CreateWork(request.Folder, request.JunkPath, request.RepoPath, request.Passphrase, request.PeerFingerprint ?? "");
    return Results.Json(new { project = p, workFingerprint = CryptoService.EncryptionFingerprint(p.WorkRecipient!) });
});
app.MapPost("/api/projects/{id}/attach-work-key", async (string id, AttachWorkKeyRequest request, SyncEngine engine) =>
    Results.Json(await engine.AttachWorkKey(id, request.Recipient, request.Fingerprint)));
app.MapPost("/api/projects/{id}/sync", async (string id, SyncRequest request, SyncEngine engine) =>
    Results.Json(await engine.SyncJunk(id, request.Passphrase, request.Push, request.MaxCommits)));
app.MapPost("/api/projects/{id}/inbox", async (string id, PassphraseRequest request, SyncEngine engine) => Results.Json((await engine.Inbox(id, request.Passphrase)).Select(x => new { x.ChangeId, x.PreviousChangeId, x.SourceCommit, x.Message, x.Direction, x.BaseDigest, x.ResultDigest })));
app.MapPost("/api/projects/{id}/apply", async (string id, ApplyRequest request, SyncEngine engine) => Results.Json(await engine.Apply(id, request.ChangeId, request.Passphrase)));
app.MapPost("/api/projects/{id}/confirm", async (string id, PassphraseRequest request, SyncEngine engine) => Results.Json(await engine.Confirm(id, request.Passphrase)));
app.MapPost("/api/projects/{id}/recover", async (string id, PassphraseRequest request, SyncEngine engine) => Results.Json(await engine.Recover(id, request.Passphrase)));
app.Run();

public partial class Program;
public sealed record CreateProject(string Folder, string JunkPath, string RepoPath, string Passphrase, string? PeerFingerprint);
public sealed record PassphraseRequest(string Passphrase);
public sealed record SyncRequest(string Passphrase, bool Push, int MaxCommits = 0);
public sealed record AttachWorkKeyRequest(string Recipient, string Fingerprint);
public sealed record ApplyRequest(string ChangeId, string Passphrase);
