using System.Net;
using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public sealed class CsrfRegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private const string TokenRoute = "/api/antiforgery/token";
    private const string HeaderName = "X-CSRF-TOKEN";

    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    private sealed record CreatedResponse(Guid Id);
    private sealed record DetailsResponse(string Title, string Description);
    private sealed record ProblemResponse(string Title);

    [Fact]
    public async Task RegCsrf01_PutWithoutValidToken_IsRejected_StateUnchanged_ThenValidPairSucceeds()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        await alice.UseAntiforgeryTokenAsync(TokenRoute, HeaderName);
        var title = "Csrf-" + Guid.NewGuid().ToString("N")[..12];
        using var created = await alice.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "before",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1)
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<CreatedResponse>())!.Id;
        var url = $"/api/incidents/{id}";

        alice.DefaultRequestHeaders.Remove(HeaderName);
        using var noToken = await alice.PutAsJsonAsync(url, new { title, description = "no-token" });
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        Assert.Equal("Antiforgery token is missing or invalid.",
            (await noToken.Content.ReadFromJsonAsync<ProblemResponse>())!.Title);
        Assert.Equal("before", (await alice.GetFromJsonAsync<DetailsResponse>(url))!.Description);

        using var invalidRequest = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = JsonContent.Create(new { title, description = "invalid-token" })
        };
        invalidRequest.Headers.Add(HeaderName, "not-a-real-token");
        using var invalid = await alice.SendAsync(invalidRequest);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal("before", (await alice.GetFromJsonAsync<DetailsResponse>(url))!.Description);

        await alice.UseAntiforgeryTokenAsync(TokenRoute, HeaderName);
        using var accepted = await alice.PutAsJsonAsync(url, new { title, description = "after" });
        Assert.Equal(HttpStatusCode.NoContent, accepted.StatusCode);
        Assert.Equal("after", (await alice.GetFromJsonAsync<DetailsResponse>(url))!.Description);
    }
}