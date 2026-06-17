using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ApiGateway.Models;
using ApiGateway.Services;

namespace ApiGateway.Controllers
{
    /// <summary>
    /// Handles Multi-Factor Authentication (MFA) setup and verification endpoints.
    ///
    /// Flow:
    ///   1. POST /api/auth/mfa/setup   – generate a TOTP secret and return a QR-code URI.
    ///   2. POST /api/auth/mfa/verify  – validate the 6-digit code from the authenticator app.
    /// </summary>
    [ApiController]
    [Route("api/auth/mfa")]
    public class MfaController : ControllerBase
    {
        private readonly IMfaService _mfaService;
        private readonly ILogger<MfaController> _logger;

        public MfaController(IMfaService mfaService, ILogger<MfaController> logger)
        {
            _mfaService = mfaService;
            _logger = logger;
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/mfa/setup
        // -----------------------------------------------------------------------

        /// <summary>
        /// Generates a new TOTP secret for the authenticated user and returns a
        /// QR-code URI that can be scanned by an authenticator app.
        /// </summary>
        /// <returns>MFA setup payload containing the secret and QR-code URI.</returns>
        [HttpPost("setup")]
        [Authorize]
        [ProducesResponseType(typeof(MfaSetupResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        public IActionResult Setup()
        {
            var username = User.Identity?.Name ?? User.FindFirst("username")?.Value;

            if (string.IsNullOrWhiteSpace(username))
            {
                _logger.LogWarning("MFA setup attempted without a resolvable username.");
                return Unauthorized(new ErrorResponse
                {
                    Error = "Unauthorized",
                    Message = "Unable to determine the authenticated user.",
                    StatusCode = 401
                });
            }

            _logger.LogInformation("MFA setup initiated for user: {Username}", username);

            var secret = _mfaService.GenerateSecret(username);
            var qrUri  = _mfaService.BuildQrCodeUri(username, secret);

            return Ok(new MfaSetupResponse
            {
                Secret    = secret,
                QrCodeUri = qrUri,
                Message   = "Scan the QR code with your authenticator app, then verify with /api/auth/mfa/verify."
            });
        }

        // -----------------------------------------------------------------------
        // POST /api/auth/mfa/verify
        // -----------------------------------------------------------------------

        /// <summary>
        /// Validates the 6-digit TOTP code provided by the user.
        /// Returns 200 OK on success, 401 Unauthorized on failure.
        /// </summary>
        /// <param name="request">MFA verification request containing the code.</param>
        /// <returns>Success or failure response.</returns>
        [HttpPost("verify")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
        public IActionResult Verify([FromBody] MfaVerifyRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Code))
            {
                return BadRequest(new ErrorResponse
                {
                    Error      = "InvalidRequest",
                    Message    = "A non-empty MFA code is required.",
                    StatusCode = 400
                });
            }

            // Resolve username from JWT claims or from the request body (pre-auth scenario)
            var username = User.Identity?.Name
                        ?? User.FindFirst("username")?.Value
                        ?? request.Username;

            if (string.IsNullOrWhiteSpace(username))
            {
                return BadRequest(new ErrorResponse
                {
                    Error      = "InvalidRequest",
                    Message    = "Username could not be determined.",
                    StatusCode = 400
                });
            }

            _logger.LogInformation("MFA verification attempt for user: {Username}", username);

            var isValid = _mfaService.ValidateCode(username, request.Code);

            if (!isValid)
            {
                _logger.LogWarning("MFA verification failed for user: {Username}", username);
                return Unauthorized(new ErrorResponse
                {
                    Error      = "InvalidMfaCode",
                    Message    = "The provided MFA code is incorrect or has expired.",
                    StatusCode = 401
                });
            }

            _logger.LogInformation("MFA verification succeeded for user: {Username}", username);
            return Ok(new { Message = "MFA verification successful.", MfaVerified = true });
        }
    }

    // -----------------------------------------------------------------------
    // Request / Response models specific to MFA
    // -----------------------------------------------------------------------

    /// <summary>Request body for MFA code verification.</summary>
    public class MfaVerifyRequest
    {
        /// <summary>The 6-digit TOTP code from the authenticator app.</summary>
        public string Code { get; set; } = string.Empty;

        /// <summary>
        /// Optional: username when the caller is not yet fully authenticated
        /// (i.e., between first-factor and second-factor steps).
        /// </summary>
        public string? Username { get; set; }
    }

    /// <summary>Response body returned after a successful MFA setup.</summary>
    public class MfaSetupResponse
    {
        /// <summary>Base32-encoded TOTP shared secret.</summary>
        public string Secret { get; set; } = string.Empty;

        /// <summary>otpauth:// URI for QR-code generation.</summary>
        public string QrCodeUri { get; set; } = string.Empty;

        /// <summary>Human-readable instruction message.</summary>
        public string Message { get; set; } = string.Empty;
    }
}
