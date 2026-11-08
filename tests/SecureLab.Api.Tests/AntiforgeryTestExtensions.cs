using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

public static class AntiforgeryTestExtensions
{
    private sealed record TokenResponse(string Token);

    public static async Task UseAntiforgeryTokenAsync(
        this HttpClient client, string tokenRoute, string headerName)
    {
        client.DefaultRequestHeaders.Remove(headerName);
        using var response = await client.GetAsync(tokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
            throw new InvalidOperationException("Missing request token.");
        client.DefaultRequestHeaders.Add(headerName, body.Token);
    }
}