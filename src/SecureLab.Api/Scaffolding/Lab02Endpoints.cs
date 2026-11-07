using SecureLab.Api.Security;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
        {
            if (!Guid.TryParse(httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var userId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
            var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

            var query = db.Incidents
                .AsNoTracking()
                .Where(i => isAnalyst || i.OwnerUserId == userId);

            if (!string.IsNullOrEmpty(q))
            {
                var escapedQ = q.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_");
                var pattern = $"%{escapedQ}%";

                query = query.Where(i =>
                    EF.Functions.ILike(i.Title, pattern) ||
                    EF.Functions.ILike(i.Description, pattern));
            }

            if (!string.IsNullOrEmpty(sortBy) && sortBy != "severity" && sortBy != "status" && sortBy != "createdAtUtc")
            {
                return Results.Problem("Недопустиме значення sortBy", statusCode: 400);
            }

            query = sortBy switch
            {
                "severity" => query.OrderBy(i => i.Severity).ThenBy(i => i.Id),
                "status" => query.OrderBy(i => i.Status).ThenBy(i => i.Id),
                _ => query.OrderByDescending(i => i.CreatedAtUtc).ThenBy(i => i.Id)
            };

            var rows = await query.Take(50).ToListAsync(ct);

            return Results.Ok(rows.Select(row => new
            {
                row.Id,
                row.Title,
                row.Description,
                Severity = row.Severity.ToString(),
                Status = row.Status.ToString(),
                row.CreatedAtUtc
            }));
        }).RequireAuthorization().RequireRateLimiting("incident-search");


        app.MapPost("/api/incidents", async (CreateIncidentRequest request, HttpContext httpContext, SecureLabDbContext db, CancellationToken ct) =>
        {
            var idClaim = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(idClaim, out var ownerId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            var errors = new Dictionary<string, string[]>();
            var now = DateTimeOffset.UtcNow;

            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            if (string.IsNullOrEmpty(title))
                errors["title"] = ["Title is required."];
            else if (title.Length > 160)
                errors["title"] = ["Title cannot exceed 160 characters."];

            if (string.IsNullOrEmpty(description))
                errors["description"] = ["Description is required."];
            else if (description.Length > 4000)
                errors["description"] = ["Description cannot exceed 4000 characters."];

            if (!Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity) || !Enum.IsDefined(severity))
            {
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
            }

            if (request.OccurredAtUtc is null)
            {
                errors["occurredAtUtc"] = ["OccurredAtUtc is required."];
            }
            else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
            {
                errors["occurredAtUtc"] = ["Дата не може випереджати час сервера більш ніж на 5 хвилин."];
            }

            if (errors.Count == 0 && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical))
            {
                if (description.Length < 40)
                {
                    errors["description"] = ["Для критичності High або Critical опис має містити щонайменше 40 символів."];
                }
            }

            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors);
            }

            var isDuplicate = await db.Incidents.AnyAsync(i =>
                i.Title == title &&
                i.Status != IncidentStatus.Closed, ct);

            if (isDuplicate)
            {
                return Results.Problem("Активний інцидент з таким заголовком вже існує.", statusCode: 409);
            }

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = ownerId,
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = request.OccurredAtUtc!.Value,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            return Results.Created($"/api/incidents/{incident.Id}", new
            {
                incident.Id,
                incident.Title,
                Severity = incident.Severity.ToString(),
                Status = incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc
            });
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();
}
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);
