using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using ApiGateway.Models;
using ApiGateway.Services;

namespace ApiGateway.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthController> _logger;
        private readonly IEmailSender _emailSender;

        // RFC 5322-inspired regex for high-fidelity email validation.
        // Covers the vast majority of real-world addresses while rejecting clearly malformed ones.
        private static readonly Regex EmailRegex = new(
            @"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            TimeSpan.FromMilliseconds(100));

        public AuthController(
            IConfiguration configuration,
            ILogger<AuthController> logger,
            IEmailSender emailSender)
        {
            _configuration = configuration;
            _logger = logger;
            _emailSender = emailSender;
        }

        /// <summary>
        /// Generate JWT token for testing purposes.
        /// </summary>
        /// <param name="request">Login request containing username and password.</param>
        /// <returns>JWT token on success; 400 on missing credentials.</returns>
        [HttpPost("token")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        public IActionResult GenerateToken([FromBody] LoginRequest request)
        {
            _logger.LogInformation("Token generation requested for user: {Username}", request.Username);

            try
            {
                // Simple validation for demo purposes
                if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
                {
                    return BadRequest(new ErrorResponse
                    {
                        Error = "InvalidCredentials",
                        Message = "Username and password are required",
                        StatusCode = 400
                    });
                }

                // For demo purposes, accept any non-empty credentials.
                // In production, validate against a user store.
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.UTF8.GetBytes(
                    _configuration["Jwt:Key"] ?? "default-secret-key-for-development");

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, request.Username),
                        new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                        new Claim("username", request.Username)
                    }),
                    Expires = DateTime.UtcNow.AddHours(1),
                    Issuer = _configuration["Jwt:Issuer"],
                    Audience = _configuration["Jwt:Audience"],
                    SigningCredentials = new SigningCredentials(
                        new SymmetricSecurityKey(key),
                        SecurityAlgorithms.HmacSha256Signature)
                };

                var token = tokenHandler.CreateToken(tokenDescriptor);
                var tokenString = tokenHandler.WriteToken(token);

                _logger.LogInformation("Token generated successfully for user: {Username}", request.Username);

                return Ok(new
                {
                    token = tokenString,
                    expires = tokenDescriptor.Expires,
                    tokenType = "Bearer"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating token for user: {Username}", request.Username);
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "TokenGenerationFailed",
                    Message = "An error occurred while generating the token",
                    StatusCode = 500
                });
            }
        }

        /// <summary>
        /// Register a user by email address and trigger a verification email.
        /// </summary>
        /// <remarks>
        /// - Returns 400 if the email format is invalid (RFC 5322 check).
        /// - Returns 200 regardless of whether the address is already registered
        ///   to prevent user-enumeration attacks.
        /// - Returns 500 if the downstream email service is unavailable.
        /// </remarks>
        /// <param name="request">Registration request containing the email address.</param>
        /// <returns>200 OK on success; 400 on invalid input; 500 on email delivery failure.</returns>
        [HttpPost("register")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status500InternalServerError)]
        public async Task<IActionResult> Register([FromBody] RegisterEmailRequest request)
        {
            _logger.LogInformation("Registration attempt received");

            // Null / missing body guard
            if (request == null)
            {
                return BadRequest(new ErrorResponse
                {
                    Error = "InvalidRequest",
                    Message = "Request body is required",
                    StatusCode = 400
                });
            }

            // Trim and normalise before validation (constitution: inputs must be trimmed/case-normalised)
            var email = (request.Email ?? string.Empty).Trim().ToLowerInvariant();

            if (string.IsNullOrEmpty(email) || !EmailRegex.IsMatch(email))
            {
                _logger.LogWarning("Registration rejected: invalid email format");
                return BadRequest(new ErrorResponse
                {
                    Error = "InvalidEmail",
                    Message = "The provided email address is not valid",
                    StatusCode = 400
                });
            }

            try
            {
                // Send verification email asynchronously.
                // Persistence / user creation is out-of-scope for this story.
                await _emailSender.SendEmailAsync(
                    email,
                    "Verify your email address",
                    "Please verify your email address by clicking the link in this message.");

                _logger.LogInformation("Verification email dispatched (email omitted for PII)");

                // Always return 200 for valid emails — do not reveal registration status
                // to prevent user enumeration (constitution + spec requirement).
                return Ok(new
                {
                    message = "If this email address is valid, a verification email has been sent."
                });
            }
            catch (Exception ex)
            {
                // Log without PII beyond what is operationally necessary
                _logger.LogError(ex, "Email delivery failed during registration");

                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponse
                {
                    Error = "EmailDeliveryFailed",
                    Message = "Unable to send verification email. Please try again later.",
                    StatusCode = 500
                });
            }
        }
    }

    /// <summary>
    /// Request model for the token endpoint.
    /// </summary>
    public class LoginRequest
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
