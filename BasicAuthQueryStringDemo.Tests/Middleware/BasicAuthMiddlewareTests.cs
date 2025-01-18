using System.Text;
using BasicAuthQueryStringDemo.Infrastructure.Configuration;
using BasicAuthQueryStringDemo.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Shouldly;

namespace BasicAuthQueryStringDemo.Tests.Middleware;

public class BasicAuthMiddlewareTests
{

    [Fact]
    public async Task Should_ReturnUnauthoried_When_NoCredentialProvided()
    {
        // Arrange
        Mock<ILogger<BasicAuthMiddleware>> logger = new();
        Mock<IOptions<BasicAuth>> options = new();

        BasicAuth basicAuth = new BasicAuth { Username = "testuser", Password = "testpass" };
        options.Setup(x => x.Value).Returns(basicAuth);
        RequestDelegate next = (HttpContext context) => Task.CompletedTask;

        DefaultHttpContext context = new();
        BasicAuthMiddleware middleware = new(next, logger.Object, options.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task Should_ReturnBadRequest_When_InvalidBase64Provided()
    {
        // Arrange
        Mock<ILogger<BasicAuthMiddleware>> logger = new();
        Mock<IOptions<BasicAuth>> options = new();

        BasicAuth basicAuth = new BasicAuth { Username = "testuser", Password = "testpass" };
        options.Setup(x => x.Value).Returns(basicAuth);
        RequestDelegate next = (HttpContext context) => Task.CompletedTask;

        DefaultHttpContext context = new();
        QueryString queryString = new("?credentials=invalid-base64");
        context.Request.QueryString = queryString;
        BasicAuthMiddleware middleware = new(next, logger.Object, options.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task Should_ReturnBadRequest_When_InvalidCredentialFormatProvided()
    {
        // Arrange
        Mock<ILogger<BasicAuthMiddleware>> logger = new();
        Mock<IOptions<BasicAuth>> options = new();

        BasicAuth basicAuth = new BasicAuth { Username = "testuser", Password = "testpass" };
        options.Setup(x => x.Value).Returns(basicAuth);
        RequestDelegate next = (HttpContext context) => Task.CompletedTask;

        DefaultHttpContext context = new();
        string invalidCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("invalid-format"));
        QueryString queryString = new($"?credentials={invalidCredentials}");
        context.Request.QueryString = queryString;
        BasicAuthMiddleware middleware = new(next, logger.Object, options.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task Should_ReturnUnautorized_When_InvalidCredentialsProvided()
    {
        // Arrange
        Mock<ILogger<BasicAuthMiddleware>> logger = new();
        Mock<IOptions<BasicAuth>> options = new();

        BasicAuth basicAuth = new BasicAuth { Username = "testuser", Password = "testpass" };
        options.Setup(x => x.Value).Returns(basicAuth);
        RequestDelegate next = (HttpContext context) => Task.CompletedTask;
        BasicAuthMiddleware middleware = new(next, logger.Object, options.Object);

        DefaultHttpContext context = new();
        string invalidCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("wronguser:wrongpassword"));
        QueryString queryString = new($"?credentials={invalidCredentials}");
        context.Request.QueryString = queryString;

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task Should_CallNext_When_ValidCredentialsProvided()
    {
        // Arrange
        Mock<ILogger<BasicAuthMiddleware>> logger = new();
        Mock<IOptions<BasicAuth>> options = new();

        BasicAuth basicAuth = new BasicAuth { Username = "testuser", Password = "testpass" };
        options.Setup(x => x.Value).Returns(basicAuth);

        bool nextCalled = false;
        RequestDelegate next = (HttpContext context) =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        };

        BasicAuthMiddleware middleware = new(next, logger.Object, options.Object);

        DefaultHttpContext context = new();
        string validCredentials = Convert.ToBase64String(Encoding.UTF8.GetBytes("testuser:testpass"));
        QueryString queryString = new($"?credentials={validCredentials}");
        context.Request.QueryString = queryString;

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        nextCalled.ShouldBe(true);
        context.Response.StatusCode.ShouldBe(StatusCodes.Status200OK);
    }
}
