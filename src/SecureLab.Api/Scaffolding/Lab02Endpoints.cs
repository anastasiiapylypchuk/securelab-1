using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

// Навчальний старт ЛР 02. Запускати лише з локальними штучними даними.
public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var order = sortBy switch
            {
                null or "" or "createdAtUtc" => "created_at_utc DESC",
                "severity" => "severity", "status" => "status", _ => sortBy
            };
            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "")
                + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + order + " LIMIT 50";
            var rows = await db.Incidents.FromSqlRaw(sql).AsNoTracking().ToListAsync(ct);
            return Results.Ok(rows.Select(row => new
            {
                row.Id, row.Title, row.Description,
                Severity = row.Severity.ToString(), Status = row.Status.ToString(), row.CreatedAtUtc
            }));
        });
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
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
                OwnerUserId = DbSeeder.AliceId,
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
        });
    }
}

public sealed record CreateIncidentRequest(
    string? Title, string? Description, string? Severity, DateTimeOffset? OccurredAtUtc);
