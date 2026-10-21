using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using System.Security.Claims;
using SecureLab.Api.Data;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();
        
        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident");
        
        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident");
        
        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident");
        
        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetIncidentSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();
        
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithName("GetIncidentComment")
            .RequireAuthorization();
        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        if (!Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            return Results.Challenge();
        }
        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);

        return Results.Ok(await queries.GetListAsync(parsedStatus, userId, isAnalyst, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var incident = await queries.GetDetailsAsync(id, userId, isAnalyst, cancellationToken);
        return incident is null ? IncidentNotFound() : Results.Ok(incident);
    }
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        var comment = await queries.GetCommentAsync(id, userId, isAnalyst, cancellationToken);
        return comment is null ? IncidentNotFound() : Results.Ok(comment);
    }
    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canUpdate = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            return Results.Forbid();
        }

        var title = request.Title?.Trim() ?? "";
        var description = request.Description?.Trim() ?? "";
        var errors = new Dictionary<string, string[]>();

        if (string.IsNullOrEmpty(title))
            errors["title"] = ["Title is required."];
        else if (title.Length > 160)
            errors["title"] = ["Title cannot exceed 160 characters."];

        if (string.IsNullOrEmpty(description))
            errors["description"] = ["Description is required."];
        else if (description.Length > 4000)
            errors["description"] = ["Description cannot exceed 4000 characters."];
        else if ((incident.Severity == IncidentSeverity.High || incident.Severity == IncidentSeverity.Critical)
                 && description.Length < 40)
            errors["description"] = ["Для критичності High або Critical опис має містити щонайменше 40 символів."];

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            return Results.Forbid();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }
    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();
        }

        var canTriage = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            logger.LogWarning(
                "authorization.denied subject={SubjectId} action={Action} "
                + "resource={ResourceId} result={Result} "
                + "occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
                httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
                "incident.triage",
                incident.Id,
                "denied",
                DateTimeOffset.UtcNow,
                Activity.Current?.Id ?? httpContext.TraceIdentifier);
            return Results.Forbid();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід неможливий",
                detail: "Triage дозволено лише для статусу New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        _ = Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var actorId);
        var now = DateTimeOffset.UtcNow;

        dbContext.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actorId,
            OldStatus = incident.Status,
            NewStatus = IncidentStatus.Triaged,
            Note = "Triage",
            CreatedAtUtc = now
        });
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }
    private static async Task<IResult> GetSeveritySummaryAsync(
    IncidentQueries queries,
    CancellationToken cancellationToken)
    {
        var summary = await queries.GetSeveritySummaryAsync(cancellationToken);
        return Results.Ok(summary);
    }
}
