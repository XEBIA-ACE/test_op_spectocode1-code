using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using ApiGateway.Controllers;
using ApiGateway.Models;
using ApiGateway.Services;
using Xunit;

namespace ApiGateway.Tests.Controllers
{
    /// <summary>
    /// Unit tests for <see cref="AuthController"/>.
    ///
    /// Coverage targets (per spec + constitution):
    ///   - POST /api/auth/register — happy path (valid email, IEmailSender called, 200 OK)
    ///   - POST /api/auth/register — invalid email formats (400 + structured ErrorResponse)
    ///   - POST /api/auth/register — IEmailSender throws (500 + structured ErrorResponse)
    ///   - POST /api/auth/token   — existing token-generation behaviour (regression guard)
    /// </summary>
    public class AuthControllerTests
    {
        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static AuthController CreateController(
            IEmailSender? emailSender = null,
            IConfiguration? configuration = null)
        {
            var config = configuration ?? BuildDefaultConfiguration();
            var logger = new Mock<ILogger<AuthController>>().Object;
            var sender = emailSender ?? new Mock<IEmailSender>().Object;
            return new AuthController(config, logger, sender);
        }

        private static IConfiguration BuildDefaultConfiguration()
        {
            var inMemory = new Dictionary<string, string?>
            {
                ["Jwt:Key"]      = "test-secret-key-for-unit-tests-256-bits-long!!",
                ["Jwt:Issuer"]   = "ApiGateway",
                ["Jwt:Audience"] = "ApiGatewayUsers"
            };
            return new ConfigurationBuilder()
                .AddInMemoryCollection(inMemory)
                .Build();
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/register — Happy Path
        // -----------------------------------------------------------------------

        [Fact]
        public async Task Register_ValidEmail_Returns200Ok()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert — HTTP 200
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
        }

        [Fact]
        public async Task Register_ValidEmail_CallsIEmailSenderOnce()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            await controller.Register(request);

            // Assert — IEmailSender.SendEmailAsync called exactly once with the normalised address
            mockSender.Verify(
                s => s.SendEmailAsync(
                    "user@example.com",   // trimmed + lowercased
                    It.IsAny<string>(),
                    It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Register_ValidEmail_ResponseBodyContainsMessage()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "alice@domain.org" };

            // Act
            var result = await controller.Register(request);

            // Assert — response body has a non-empty message property
            var okResult = Assert.IsType<OkObjectResult>(result);
            var body = okResult.Value;
            Assert.NotNull(body);

            // Use reflection to read the anonymous-type "message" property
            var messageProp = body!.GetType().GetProperty("message");
            Assert.NotNull(messageProp);
            var messageValue = messageProp!.GetValue(body) as string;
            Assert.False(string.IsNullOrWhiteSpace(messageValue));
        }

        [Fact]
        public async Task Register_EmailWithUpperCase_NormalisesAndSucceeds()
        {
            // Arrange — email with mixed case; controller must normalise before sending
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "User@Example.COM" };

            // Act
            var result = await controller.Register(request);

            // Assert — 200 OK and sender called with lowercased address
            Assert.IsType<OkObjectResult>(result);
            mockSender.Verify(
                s => s.SendEmailAsync("user@example.com", It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task Register_EmailWithLeadingTrailingSpaces_TrimsAndSucceeds()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "  trimmed@example.com  " };

            // Act
            var result = await controller.Register(request);

            // Assert
            Assert.IsType<OkObjectResult>(result);
            mockSender.Verify(
                s => s.SendEmailAsync("trimmed@example.com", It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/register — Invalid Email Formats → 400
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("")]                        // empty string
        [InlineData("   ")]                     // whitespace only
        [InlineData("notanemail")]              // no @ symbol
        [InlineData("missing@")]               // no domain
        [InlineData("@nodomain.com")]          // no local part
        [InlineData("double@@domain.com")]     // double @
        [InlineData("spaces in@email.com")]    // space in local part
        [InlineData("missing.tld@domain")]     // no TLD dot
        [InlineData("plainaddress")]           // completely plain
        [InlineData("user@.com")]              // domain starts with dot
        public async Task Register_InvalidEmail_Returns400BadRequest(string invalidEmail)
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            var result = await controller.Register(request);

            // Assert — HTTP 400
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
        }

        [Theory]
        [InlineData("")]
        [InlineData("notanemail")]
        [InlineData("missing@")]
        public async Task Register_InvalidEmail_ReturnsStructuredErrorResponse(string invalidEmail)
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            var result = await controller.Register(request);

            // Assert — body is a structured ErrorResponse
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            var errorResponse = Assert.IsType<ErrorResponse>(badRequest.Value);
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Error));
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Message));
            Assert.Equal(400, errorResponse.StatusCode);
        }

        [Theory]
        [InlineData("")]
        [InlineData("notanemail")]
        [InlineData("missing@")]
        public async Task Register_InvalidEmail_DoesNotCallEmailSender(string invalidEmail)
        {
            // Arrange — IEmailSender must NOT be invoked for invalid addresses
            var mockSender = new Mock<IEmailSender>();
            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = invalidEmail };

            // Act
            await controller.Register(request);

            // Assert
            mockSender.Verify(
                s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Never);
        }

        [Fact]
        public async Task Register_NullRequest_Returns400BadRequest()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            var controller = CreateController(emailSender: mockSender.Object);

            // Act
            var result = await controller.Register(null!);

            // Assert
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
            var errorResponse = Assert.IsType<ErrorResponse>(badRequest.Value);
            Assert.Equal(400, errorResponse.StatusCode);
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/register — IEmailSender throws → 500
        // -----------------------------------------------------------------------

        [Fact]
        public async Task Register_EmailSenderThrowsException_Returns500()
        {
            // Arrange — simulate downstream email service outage
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new InvalidOperationException("SMTP server unavailable"));

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert — HTTP 500
            var serverError = Assert.IsType<ObjectResult>(result);
            Assert.Equal(StatusCodes.Status500InternalServerError, serverError.StatusCode);
        }

        [Fact]
        public async Task Register_EmailSenderThrowsException_ReturnsStructuredErrorResponse()
        {
            // Arrange
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new InvalidOperationException("SMTP server unavailable"));

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert — body is a structured ErrorResponse with 500 status code
            var serverError = Assert.IsType<ObjectResult>(result);
            var errorResponse = Assert.IsType<ErrorResponse>(serverError.Value);
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Error));
            Assert.False(string.IsNullOrWhiteSpace(errorResponse.Message));
            Assert.Equal(500, errorResponse.StatusCode);
        }

        [Fact]
        public async Task Register_EmailSenderThrowsException_ErrorResponseDoesNotLeakInternalDetails()
        {
            // Arrange — security: internal exception message must NOT be surfaced to the client
            var internalMessage = "Connection string: Server=prod-db;Password=s3cr3t";
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new Exception(internalMessage));

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "user@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert — client-facing message must not contain the raw exception text
            var serverError = Assert.IsType<ObjectResult>(result);
            var errorResponse = Assert.IsType<ErrorResponse>(serverError.Value);
            Assert.DoesNotContain(internalMessage, errorResponse.Message ?? string.Empty);
            Assert.DoesNotContain(internalMessage, errorResponse.Details ?? string.Empty);
        }

        [Fact]
        public async Task Register_EmailSenderThrowsTaskCanceledException_Returns500()
        {
            // Arrange — simulate timeout / cancellation from email provider
            var mockSender = new Mock<IEmailSender>();
            mockSender
                .Setup(s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ThrowsAsync(new TaskCanceledException("Email send timed out"));

            var controller = CreateController(emailSender: mockSender.Object);
            var request = new RegisterEmailRequest { Email = "timeout@example.com" };

            // Act
            var result = await controller.Register(request);

            // Assert
            var serverError = Assert.IsType<ObjectResult>(result);
            Assert.Equal(StatusCodes.Status500InternalServerError, serverError.StatusCode);
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/token — Regression guard for existing behaviour
        // -----------------------------------------------------------------------

        [Fact]
        public void GenerateToken_ValidCredentials_Returns200WithToken()
        {
            // Arrange
            var controller = CreateController();
            var request = new LoginRequest { Username = "testuser", Password = "testpass" };

            // Act
            var result = controller.GenerateToken(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
            Assert.NotNull(okResult.Value);
        }

        [Theory]
        [InlineData("", "password")]
        [InlineData("username", "")]
        [InlineData("", "")]
        public void GenerateToken_MissingCredentials_Returns400(string username, string password)
        {
            // Arrange
            var controller = CreateController();
            var request = new LoginRequest { Username = username, Password = password };

            // Act
            var result = controller.GenerateToken(request);

            // Assert
            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
            var errorResponse = Assert.IsType<ErrorResponse>(badRequest.Value);
            Assert.Equal(400, errorResponse.StatusCode);
        }
    }
}
