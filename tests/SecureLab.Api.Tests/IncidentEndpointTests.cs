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

    private static readonly Dictionary<string, HttpClient> Sessions = new();
    private static readonly SemaphoreSlim SessionsLock = new(1, 1);

    private async Task<HttpClient> LoginOnceAsync(string userName)
    {
        await SessionsLock.WaitAsync();
        try
        {
            if (!Sessions.TryGetValue(userName, out var client))
            {
                client = await factory.LoginAsync(userName, StudyPassword);
                await client.UseAntiforgeryTokenAsync("/api/antiforgery/token", "X-CSRF-TOKEN");
                Sessions[userName] = client;
            }
            return client;
        }
        finally
        {
            SessionsLock.Release();
        }
    }

    [Fact]
    public async Task GetList_AsReporter_ReturnsOnlyOwnIncidents()
    {
        var alice = await LoginOnceAsync("alice");
        var incidents = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetList_AsAnalyst_ReturnsAllIncidents()
    {
        var morgan = await LoginOnceAsync("morgan");
        var incidents = await morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");

        Assert.NotNull(incidents);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(incidents, incident => incident.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        var alice = await LoginOnceAsync("alice");
        using var response = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        var alice = await LoginOnceAsync("alice");
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
        var alice = await LoginOnceAsync("alice");

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
        var alice = await LoginOnceAsync("alice");
        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceIncidentId, doc.RootElement.GetProperty("id").GetGuid());
    }

    [Fact]
    public async Task GetDetails_AsOtherReporter_Returns404_SameAsUnknownId_AndLeaksNothing()
    {
        var alice = await LoginOnceAsync("alice");

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
        var morgan = await LoginOnceAsync("morgan");
        using var response = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    private static async Task<Guid> CreateIncidentAsync(HttpClient client)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"Auth-{Guid.NewGuid():N}",
            description = "Опис тестового інциденту для перевірки авторизації.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return doc.RootElement.GetProperty("id").GetGuid();
    }

    [Fact]
    public async Task Update_AsOwner_ChangesContent()
    {
        var alice = await LoginOnceAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = "Нова назва власника", description = "Новий опис від власника інциденту." });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            using var doc = JsonDocument.Parse(await alice.GetStringAsync($"/api/incidents/{id}"));
            Assert.Equal("Нова назва власника", doc.RootElement.GetProperty("title").GetString());
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Update_AsOtherReporter_Returns404_AndDoesNotChangeIncident()
    {
        var alice = await LoginOnceAsync("alice");
        var bob = await LoginOnceAsync("bob");
        var id = await CreateIncidentAsync(alice);
        try
        {
            var before = await alice.GetStringAsync($"/api/incidents/{id}");

            using var response = await bob.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = "Змінено Бобом", description = "Цей текст не повинен зберегтися." });

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            Assert.Equal(before, await alice.GetStringAsync($"/api/incidents/{id}"));
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Update_AsAnalyst_Returns403_AndDoesNotChangeIncident()
    {
        var alice = await LoginOnceAsync("alice");
        var morgan = await LoginOnceAsync("morgan");
        var id = await CreateIncidentAsync(alice);
        try
        {
            var before = await alice.GetStringAsync($"/api/incidents/{id}");

            using var response = await morgan.PutAsJsonAsync($"/api/incidents/{id}",
                new { title = "Змінено аналітиком", description = "Цей текст не повинен зберегтися." });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(before, await alice.GetStringAsync($"/api/incidents/{id}"));
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Update_WithForgedProtectedFields_IgnoresThem()
    {
        var alice = await LoginOnceAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{id}", new
            {
                title = "Назва після підробки",
                description = "Опис після спроби підмінити захищені поля.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                severity = "Critical",
                role = "Administrator"
            });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            using var doc = JsonDocument.Parse(await alice.GetStringAsync($"/api/incidents/{id}"));
            Assert.Equal("Назва після підробки", doc.RootElement.GetProperty("title").GetString());
            Assert.Equal("New", doc.RootElement.GetProperty("status").GetString());
            Assert.Equal("Low", doc.RootElement.GetProperty("severity").GetString());
            Assert.Equal("Аліса Коваль", doc.RootElement.GetProperty("ownerDisplayName").GetString());
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Delete_AsOtherReporter_Returns404_AndIncidentRemains()
    {
        var alice = await LoginOnceAsync("alice");
        var bob = await LoginOnceAsync("bob");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await bob.DeleteAsync($"/api/incidents/{id}");

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
            using var stillThere = await alice.GetAsync($"/api/incidents/{id}");
            Assert.Equal(HttpStatusCode.OK, stillThere.StatusCode);
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Delete_AsOwner_RemovesIncident()
    {
        var alice = await LoginOnceAsync("alice");
        var id = await CreateIncidentAsync(alice);

        using var response = await alice.DeleteAsync($"/api/incidents/{id}");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        using var gone = await alice.GetAsync($"/api/incidents/{id}");
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
    }

    [Fact]
    public async Task Triage_AsOwnerReporter_Returns403_AndStatusUnchanged()
    {
        var alice = await LoginOnceAsync("alice");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await alice.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            using var doc = JsonDocument.Parse(await alice.GetStringAsync($"/api/incidents/{id}"));
            Assert.Equal("New", doc.RootElement.GetProperty("status").GetString());
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Triage_AsAnalyst_MovesNewToTriaged()
    {
        var alice = await LoginOnceAsync("alice");
        var morgan = await LoginOnceAsync("morgan");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
            using var doc = JsonDocument.Parse(await alice.GetStringAsync($"/api/incidents/{id}"));
            Assert.Equal("Triaged", doc.RootElement.GetProperty("status").GetString());
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    [Fact]
    public async Task Triage_WhenAlreadyTriaged_Returns409()
    {
        var alice = await LoginOnceAsync("alice");
        var morgan = await LoginOnceAsync("morgan");
        var id = await CreateIncidentAsync(alice);

        using var first = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);

        using var second = await morgan.PostAsync($"/api/incidents/{id}/triage", content: null);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Triage_AsOtherReporter_Returns404()
    {
        var alice = await LoginOnceAsync("alice");
        var bob = await LoginOnceAsync("bob");
        var id = await CreateIncidentAsync(alice);
        try
        {
            using var response = await bob.PostAsync($"/api/incidents/{id}/triage", content: null);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
        finally
        {
            await alice.DeleteAsync($"/api/incidents/{id}");
        }
    }

    private static readonly Guid AlicePublicCommentId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid BobPublicCommentId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid AliceInternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");

    [Fact]
    public async Task GetComment_OfOtherReportersIncident_Returns404()
    {
        var alice = await LoginOnceAsync("alice");
        using var response = await alice.GetAsync($"/api/incident-comments/{BobPublicCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("журналу автентифікації", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task GetComment_PublicOnOwnIncident_Returns200()
    {
        var alice = await LoginOnceAsync("alice");
        using var response = await alice.GetAsync($"/api/incident-comments/{AlicePublicCommentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetComment_InternalOnOwnIncident_Returns404_ForReporter()
    {
        var alice = await LoginOnceAsync("alice");
        using var response = await alice.GetAsync($"/api/incident-comments/{AliceInternalCommentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Внутрішня нотатка", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task GetComment_Internal_Returns200_ForAnalyst()
    {
        var morgan = await LoginOnceAsync("morgan");
        using var response = await morgan.GetAsync($"/api/incident-comments/{AliceInternalCommentId}");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task GetComment_Anonymous_Returns401()
    {
        using var response = await _client.GetAsync($"/api/incident-comments/{AlicePublicCommentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Search_Anonymous_Returns401()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=%D0%9F");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Search_AsReporter_DoesNotReturnOtherUsersIncidents()
    {
        var alice = await LoginOnceAsync("alice");
        var body = await alice.GetStringAsync("/api/incidents/search?q=" + Uri.EscapeDataString("Невідома спроба"));

        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), body);
        using var doc = JsonDocument.Parse(body);
        Assert.Equal(0, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task Search_AsAnalyst_ReturnsOtherUsersIncident()
    {
        var morgan = await LoginOnceAsync("morgan");
        var body = await morgan.GetStringAsync("/api/incidents/search?q=" + Uri.EscapeDataString("Невідома спроба"));

        Assert.Contains(DbSeeder.BobIncidentId.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SeveritySummary_AsReporter_CountsOnlyOwnIncidents()
    {
        var alice = await LoginOnceAsync("alice");
        var morgan = await LoginOnceAsync("morgan");

        var aliceTotal = SumCounts(await alice.GetStringAsync("/api/incidents/severity-summary"));
        var morganTotal = SumCounts(await morgan.GetStringAsync("/api/incidents/severity-summary"));

        Assert.True(aliceTotal < morganTotal);
    }

    private static int SumCounts(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var total = 0;
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            foreach (var property in item.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.Number)
                    total += property.Value.GetInt32();
            }
        }
        return total;
    }
}