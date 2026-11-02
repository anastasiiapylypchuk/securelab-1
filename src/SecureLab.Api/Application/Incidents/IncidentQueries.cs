using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        Guid currentUserId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents
            .AsNoTracking()
            .Where(incident => isAnalyst || incident.OwnerUserId == currentUserId);

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        Guid currentUserId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id
                               && (isAnalyst || incident.OwnerUserId == currentUserId))
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }
    public Task<IncidentCommentResponse?> GetCommentAsync(
        Guid commentId,
        Guid currentUserId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        return dbContext.IncidentComments
            .AsNoTracking()
            .Where(comment => comment.Id == commentId
                              && (isAnalyst
                                  || (comment.Incident.OwnerUserId == currentUserId && !comment.IsInternal)))
            .Select(comment => new IncidentCommentResponse(
                comment.Id,
                comment.Author.DisplayName,
                comment.Text,
                comment.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);
    }
    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        Guid currentUserId,
        bool isAnalyst,
        CancellationToken cancellationToken)
    {
        var dbSummary = await dbContext.Incidents
            .AsNoTracking()
            .Where(i => isAnalyst || i.OwnerUserId == currentUserId)
            .GroupBy(i => i.Severity)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Key, x => x.Count, cancellationToken);

        var result = Enum.GetValues<IncidentSeverity>()
            .OrderByDescending(s => s)
            .Select(s => new IncidentSeveritySummaryResponse(
                s.ToString(),
                dbSummary.GetValueOrDefault(s, 0)))
            .ToList();

        logger.LogInformation(
            "Severity summary built. Active groups in database: {ActiveGroupsCount}.",
            dbSummary.Count);

        return result;
    }
}
