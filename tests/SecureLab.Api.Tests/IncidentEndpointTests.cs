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

    [Fact]
    public async Task GetList_ReturnsSeededIncidents()
    {
        var incidents = await _client.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var response = await _client.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var response = await _client.GetAsync(
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
        var title = $"Regression-{Guid.NewGuid():N}";

        var requestData = new
        {
            title = title,
            description = "Це тестовий опис інциденту, який має більше 40 символів для валідації High.",
            severity = "High",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        var firstResponse = await _client.PostAsJsonAsync("/api/incidents", requestData);
        Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

        var secondResponse = await _client.PostAsJsonAsync("/api/incidents", requestData);
        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
    }

    [Fact]
    public async Task CreateIncident_InvalidDto_Returns400BadRequest()
    {
        var requestData = new
        {
            title = "",
            severity = "SuperCritical", 
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        var response = await _client.PostAsJsonAsync("/api/incidents", requestData);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Search_WithSqlInjectionPayload_ReturnsEmptyResultAnd200()
    {
        var response = await _client.GetAsync("/api/incidents/search?q=zz-no-match%27%20OR%20TRUE%20--%20");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var results = await response.Content.ReadFromJsonAsync<List<IncidentListItemResponse>>();

        Assert.NotNull(results);
        Assert.Empty(results);
    }

    [Fact]
    public async Task CreateIncident_SameTitleAndDescription_Returns400BadRequest()
    {
        var requestData = new
        {
            title = "Тестовий інцидент",
            description = "Тестовий інцидент",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        };

        var response = await _client.PostAsJsonAsync("/api/incidents", requestData);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
