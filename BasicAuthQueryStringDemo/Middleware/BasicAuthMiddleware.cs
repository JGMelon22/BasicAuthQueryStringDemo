using System.Text;
using BasicAuthQueryStringDemo.Infrastructure.Configuration;
using Microsoft.Extensions.Options;

namespace BasicAuthQueryStringDemo.Middleware;

public class BasicAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<BasicAuthMiddleware> _logger;
    private readonly IOptions<BasicAuth> _appSettings;

    public BasicAuthMiddleware(RequestDelegate next, ILogger<BasicAuthMiddleware> logger,
        IOptions<BasicAuth> appSettings)
    {
        _next = next;
        _logger = logger;
        _appSettings = appSettings;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        string base64Credentials = context.Request.Query["credentials"].ToString();

        if (!string.IsNullOrEmpty(base64Credentials))
        {
            try
            {
                byte[] decodedBytes = Convert.FromBase64String(base64Credentials);
                string decodedString = Encoding.UTF8.GetString(decodedBytes);

                string[] credentials = decodedString.Split(':');
                if (credentials.Length == 2)
                {
                    string decodedUsername = credentials[0];
                    string decodedPassword = credentials[1];

                    _logger.LogInformation("Decoded Username: {Username}, Decoded Password: {Password}", decodedUsername, decodedPassword);
                }
                else
                {
                    _logger.LogWarning("Invalid Base64 credentials format.");
                }
            }
            catch (FormatException ex)
            {
                _logger.LogError("Error decoding Base64 string: {Error}", ex.Message);
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid Base64 credentials.");
                return;
            }
        }
        else
        {
            _logger.LogWarning("No credentials found in the query string.");
        }

        await _next(context);
    }
}
