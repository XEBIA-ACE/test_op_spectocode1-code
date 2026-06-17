namespace ApiGateway.Services
{
    /// <summary>
    /// Defines the contract for Multi-Factor Authentication operations.
    /// Implementations should use a TOTP algorithm (RFC 6238) compatible
    /// with standard authenticator apps (Google Authenticator, Authy, etc.).
    /// </summary>
    public interface IMfaService
    {
        /// <summary>
        /// Generates a new Base32-encoded shared secret for a user.
        /// </summary>
        /// <param name="username">The username to associate with the secret.</param>
        /// <returns>A Base32-encoded TOTP secret.</returns>
        string GenerateSecret(string username);

        /// <summary>
        /// Builds a <c>otpauth://</c> URI suitable for encoding as a QR code.
        /// </summary>
        /// <param name="username">The account label shown in the authenticator app.</param>
        /// <param name="secret">The Base32-encoded shared secret.</param>
        /// <returns>An <c>otpauth://totp/…</c> URI string.</returns>
        string BuildQrCodeUri(string username, string secret);

        /// <summary>
        /// Validates a 6-digit TOTP code against the stored secret for the user.
        /// Allows a ±1 time-step window to account for clock skew.
        /// </summary>
        /// <param name="username">The username whose secret is used for validation.</param>
        /// <param name="code">The 6-digit code provided by the user.</param>
        /// <returns><c>true</c> if the code is valid; otherwise <c>false</c>.</returns>
        bool ValidateCode(string username, string code);
    }
}
