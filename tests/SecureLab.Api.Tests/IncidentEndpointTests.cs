using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private static string StudyPassword =>
       Environment.GetEnvironmentVariable("SeedUsers__Password")
       ?? throw new InvalidOperationException(
           "Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task GetList_ReturnsSeededIncidents()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var incidents = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");
        
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync(
            $"/api/incidents/{DbSeeder.AliceIncidentId}");
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("email", out _));
        Assert.Equal("Аліса Коваль", document.RootElement.GetProperty("ownerDisplayName").GetString());
    }

    [Fact]
    public async Task ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var script = await _client.GetStringAsync("/app.js");

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreateIncident_DuplicateTitle_Returns409Conflict()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var title = $"Regression-{Guid.NewGuid():N}";

        var requestData = new
        {
            title = title,
            description = "Це тестовий опис інциденту, який має більше 40 символів для валідації High.",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        var firstResponse = await alice.PostAsJsonAsync("/api/incidents", requestData);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        var secondResponse = await alice.PostAsJsonAsync("/api/incidents", requestData);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
    }
    [Fact]
    public async Task GetDetails_Anonymous_Returns401()
    {
        using var response = await _client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task GetDetails_AsOwner_ReturnsOwnIncident()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceIncidentId, doc.RootElement.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var foreign = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknown = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");
        var foreignBody = await foreign.Content.ReadAsStringAsync();
        var unknownBody = await unknown.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(unknown.Content.Headers.ContentType?.ToString(),
                     foreign.Content.Headers.ContentType?.ToString());
        Assert.DoesNotContain("Боб", foreignBody);
        Assert.DoesNotContain("Невідома спроба входу", foreignBody);

        using var f = JsonDocument.Parse(foreignBody);
        using var u = JsonDocument.Parse(unknownBody);
        Assert.Equal(u.RootElement.GetProperty("title").GetString(),
                     f.RootElement.GetProperty("title").GetString());
        Assert.Equal(u.RootElement.GetProperty("status").GetInt32(),
                     f.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task GetDetails_AsAnalyst_ReadsOtherUsersIncident()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
