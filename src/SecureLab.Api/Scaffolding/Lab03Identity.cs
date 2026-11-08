using RedisRateLimiting;
using StackExchange.Redis;
using SecureLab.Api.Security;
using System.Threading.RateLimiting;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        var redisConfiguration = builder.Configuration["Redis:Configuration"];
        IConnectionMultiplexer? redis = null;
        if (!string.IsNullOrWhiteSpace(redisConfiguration))
        {
            redis = ConnectionMultiplexer.Connect(redisConfiguration);
        }
        else if (!builder.Environment.IsDevelopment())
        {
            throw new InvalidOperationException("Redis:Configuration має бути передано поза Git.");
        }

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy("auth-login", httpContext =>
                RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    factory: _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 30,
                        Window = TimeSpan.FromSeconds(10),
                        QueueLimit = 0
                    }));
            options.AddPolicy("incident-search", httpContext =>
            {
                var partitionKey = "search:"
                                   + (httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "anonymous");
                return redis is null
                    ? RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 10,
                        Window = TimeSpan.FromSeconds(10),
                        QueueLimit = 0
                    })
                    : RedisRateLimitPartition.GetFixedWindowRateLimiter(partitionKey, _ => new RedisFixedWindowRateLimiterOptions
                    {
                        ConnectionMultiplexerFactory = () => redis,
                        PermitLimit = 10,
                        Window = TimeSpan.FromSeconds(10)
                    });
            });
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // ЛР 03: завершіть DTO validation та перевірки довірчої межі.
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrWhiteSpace(input.Email)
                || string.IsNullOrWhiteSpace(input.DisplayName) || string.IsNullOrEmpty(input.Password))
                return Results.BadRequest(new { message = "Registration failed" });

            if (input.UserName.Trim().Length > 256 || input.Email.Trim().Length > 256
                || input.DisplayName.Trim().Length > 120 || input.Password.Length > 100)
                return Results.BadRequest(new { message = "Registration failed" });

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = input.UserName.Trim(), Email = input.Email.Trim(),
                DisplayName = input.DisplayName.Trim()
            };
            var result = await users.CreateAsync(user, input.Password);

            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(e => e.Code).ToArray();
                if (codes.Contains("DuplicateUserName") || codes.Contains("DuplicateEmail"))
                {
                    return Results.Conflict(new { message = "User with this name or email already exists" });
                }
                return Results.BadRequest(new { message = "Registration failed" });
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me", new RegisterResponseDto(user.Id, user.UserName, user.DisplayName));
        });

        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn,
    HttpContext httpContext, ILogger<Program> logger) => 
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failure", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);

            logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                "login", result.Succeeded ? "success" : "failure", httpContext.TraceIdentifier);

            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("auth-login");

        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn,
             HttpContext httpContext, ILogger<Program> logger) =>
        {
            await signIn.SignOutAsync();
            logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                "logout", "success", httpContext.TraceIdentifier);
            return Results.NoContent();
        }).RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();

        app.MapGet("/api/me", async (HttpContext context, SecureLabDbContext db) =>
        {
            var idClaim = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!Guid.TryParse(idClaim, out var verifiedId))
                return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);

            var user = await db.Users.FindAsync(verifiedId);
            return user is null ? Results.Unauthorized() : Results.Ok(new { user.Id, user.UserName, user.DisplayName });
        }).RequireAuthorization(); 

        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(
    [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.StringLength(256)] string UserName,
    [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.EmailAddress, System.ComponentModel.DataAnnotations.StringLength(256)] string Email,
    [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.StringLength(120)] string DisplayName,
    [System.ComponentModel.DataAnnotations.Required, System.ComponentModel.DataAnnotations.StringLength(100, MinimumLength = 10)] string Password);

public sealed record RegisterResponseDto(Guid Id, string UserName, string DisplayName);
public sealed record LoginInput(string? UserName, string? Password);
