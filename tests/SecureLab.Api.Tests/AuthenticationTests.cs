using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class AuthenticationTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException(
            "Set local SeedUsers__Password outside Git.");

    private static Dictionary<string, object> NewIncident(string title) => new()
    {
        ["title"] = title,
        ["description"] = "Тестовий опис для перевірки власника.",
        ["severity"] = "Low",
        ["occurredAtUtc"] = DateTimeOffset.UtcNow.AddMinutes(-5)
    };

    [Fact]
    public async Task A01_AnonymousCreate_Returns401_NotRedirect()
    {
        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        using var response = await anonymous.PostAsJsonAsync(
            "/api/incidents", NewIncident("a01-" + Guid.NewGuid().ToString("N")));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.Equal("application/problem+json",
            response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task A02_LoginThenMe_ReturnsCurrentUser_WithSafeFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, doc.RootElement.GetProperty("id").GetGuid());
        Assert.Equal("alice", doc.RootElement.GetProperty("userName").GetString());
        foreach (var name in new[] { "password", "passwordHash", "securityStamp", "token", "cookie" })
            Assert.False(doc.RootElement.TryGetProperty(name, out _), name);
    }

    [Fact]
    public async Task A05_CreateWithForgedOwner_UsesPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        await bob.UseAntiforgeryTokenAsync("/api/antiforgery/token", "X-CSRF-TOKEN");
        var body = NewIncident("a05-" + Guid.NewGuid().ToString("N"));
        body["ownerUserId"] = DbSeeder.AliceId;

        using var response = await bob.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var createdId = doc.RootElement.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking()
            .SingleAsync(item => item.Id == createdId);

        Assert.Equal(DbSeeder.BobId, incident.OwnerUserId);
    }
    [Fact]
    public async Task A03_ForgedDemoHeader_DoesNotChangeMe()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, doc.RootElement.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task A04_CreateWithoutOwner_UsesPrincipal()
    {
        using var bob = await factory.LoginAsync("bob", StudyPassword);
        await bob.UseAntiforgeryTokenAsync("/api/antiforgery/token", "X-CSRF-TOKEN");
        var body = NewIncident("a04-" + Guid.NewGuid().ToString("N"));

        using var response = await bob.PostAsJsonAsync("/api/incidents", body);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var createdId = doc.RootElement.GetProperty("id").GetGuid();

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking()
            .SingleAsync(item => item.Id == createdId);

        Assert.Equal(DbSeeder.BobId, incident.OwnerUserId);
    }

    [Fact]
    public async Task A06_Logout_ThenMe_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        await alice.UseAntiforgeryTokenAsync("/api/antiforgery/token", "X-CSRF-TOKEN");
        using (var before = await alice.GetAsync("/api/me"))
            Assert.Equal(HttpStatusCode.OK, before.StatusCode);

        using (var logout = await alice.PostAsync("/api/auth/logout", null))
            Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        using var after = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_LookIdentical()
    {
        using var client = factory.CreateClient();

        using var unknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = "Wrong-Pass-123" });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "Wrong-Pass-123" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(unknown.StatusCode, wrong.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.MediaType,
            wrong.Content.Headers.ContentType?.MediaType);

        using var a = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync());
        using var b = JsonDocument.Parse(await wrong.Content.ReadAsStringAsync());
        foreach (var name in new[] { "type", "title", "status" })
            Assert.Equal(a.RootElement.GetProperty(name).ToString(),
                b.RootElement.GetProperty(name).ToString());
    }

    [Fact]
    public async Task Login_OverHttps_SetsHttpOnly_Secure_SameSiteLax()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });

        using var response = await client.PostAsJsonAsync(
            "/api/auth/login", new { userName = "alice", password = StudyPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        const string cookieName = ".AspNetCore.Identity.Application=";
        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(cookieName)).ToArray();
        Assert.True(matching.Length == 1);

        var attributes = matching[0].Split(';').Skip(1)
            .Select(part => part.Trim().ToLowerInvariant())
            .ToArray();
        Assert.Contains("httponly", attributes);
        Assert.Contains("secure", attributes);
        Assert.Contains("samesite=lax", attributes);
    }

    [Fact]
    public async Task Register_Success_Duplicate409_TooLongDisplayName400()
    {
        using var client = factory.CreateClient();
        var suffix = Guid.NewGuid().ToString("N")[..8];
        var request = new
        {
            userName = "reg" + suffix,
            email = "reg" + suffix + "@example.test",
            displayName = "Студент Тест",
            password = "Aa1-" + Guid.NewGuid().ToString("N")[..12]
        };

        using var first = await client.PostAsJsonAsync("/api/auth/register", request);
        Assert.Equal(HttpStatusCode.Created, first.StatusCode);
        using var doc = JsonDocument.Parse(await first.Content.ReadAsStringAsync());
        foreach (var name in new[] { "password", "passwordHash", "securityStamp", "token", "cookie" })
            Assert.False(doc.RootElement.TryGetProperty(name, out _), name);

        using var second = await client.PostAsJsonAsync("/api/auth/register", request);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);

        var other = Guid.NewGuid().ToString("N")[..8];
        using var tooLong = await client.PostAsJsonAsync("/api/auth/register", new
        {
            userName = "reg" + other,
            email = "reg" + other + "@example.test",
            displayName = new string('a', 121),
            password = request.password
        });
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
    }

    [Fact]
    public async Task Login_RateLimit_Returns429_ThenRecovers()
    {
        using var freshHost = factory.WithWebHostBuilder(_ => { });
        using var client = freshHost.CreateClient();
        var bad = new { userName = "alice", password = "Wrong-Pass-123" };

        for (var i = 0; i < 30; i++)
        {
            using var attempt = await client.PostAsJsonAsync("/api/auth/login", bad);
            Assert.Equal(HttpStatusCode.Unauthorized, attempt.StatusCode);
        }

        using var limited = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = "Wrong-Pass-123" });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        await Task.Delay(TimeSpan.FromSeconds(10) + TimeSpan.FromMilliseconds(500));

        using var recovered = await client.PostAsJsonAsync("/api/auth/login", bad);
        Assert.Equal(HttpStatusCode.Unauthorized, recovered.StatusCode);
    }
}