using System.Text;
using BasicAuthQueryStringDemo.Infrastructure.Configuration;
using Microsoft.Extensions.Options;

namespace BasicAuthQueryStringDemo.Middleware;

public class BasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<BasicAuthMiddleware> _logger;
    private readonly IOptions<BasicAuth> _appSettings;

    public BasicAuthMiddleware(
        RequestDelegate next,
        ILogger<BasicAuthMiddleware> logger,
        IOptions<BasicAuth> appSettings
    )
    {
        _next = next;
        _logger = logger;
        _appSettings = appSettings;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        string base64Credentials = context.Request.Query["credentials"].ToString();

        if (string.IsNullOrEmpty(base64Credentials))
        {
            _logger.LogWarning("No credentials found in the query string.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("Unauthorized.");
            return;
        }

        try
        {
            byte[] decodedBytes = Convert.FromBase64String(base64Credentials);
            string decodedString = Encoding.UTF8.GetString(decodedBytes);
            string[] credentials = decodedString.Split(':');

            if (credentials.Length != 2)
            {

                _logger.LogWarning("Invalid Base64 credentials format.");
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid Base64 credentials format.");
                return;
            }

            string decodedUsername = credentials[0];
            string decodedPassword = credentials[1];
            string configuredUsername = _appSettings.Value.Username;
            string configuredPassword = _appSettings.Value.Password;

            if (decodedUsername != configuredUsername || decodedPassword != configuredPassword)
            {
                _logger.LogWarning("Invalid credentials provided.");
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("Unauthorized.");
                return;
            }

            _logger.LogInformation("Authentication successful for user: {Username}", decodedUsername);
            await _next(context);

        }
        catch (FormatException ex)
        {
            _logger.LogError("Error decoding Base64 string: {Error}", ex.Message);
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid Base64 credentials.");
            return;
        }
    }
}