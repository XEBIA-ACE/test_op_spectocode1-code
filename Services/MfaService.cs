using System.Security.Cryptography;
using System.Text;

namespace ApiGateway.Services
{
    /// <summary>
    /// In-memory TOTP-based MFA service.
    ///
    /// NOTE: The secret store is in-memory only. In production, secrets must be
    /// persisted in a secure, encrypted store (e.g., Azure Key Vault, a secrets
    /// table with column-level encryption).
    /// </summary>
    public class MfaService : IMfaService
    {
        // In-memory store: username → Base32 secret
        // TODO: Replace with a persistent, encrypted store before production use.
        private static readonly Dictionary<string, string> _secrets =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly IConfiguration _configuration;
        private readonly ILogger<MfaService> _logger;

        // TOTP parameters (RFC 6238)
        private const int TimeStepSeconds = 30;
        private const int CodeDigits = 6;
        private const int AllowedWindowSteps = 1; // ±1 step for clock skew

        public MfaService(IConfiguration configuration, ILogger<MfaService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        /// <inheritdoc />
        public string GenerateSecret(string username)
        {
            // 20 random bytes → 160-bit secret (recommended minimum for TOTP)
            var secretBytes = RandomNumberGenerator.GetBytes(20);
            var secret = Base32Encode(secretBytes);
            _secrets[username] = secret;
            _logger.LogInformation("MFA secret generated for user: {Username}", username);
            return secret;
        }

        /// <inheritdoc />
        public string BuildQrCodeUri(string username, string secret)
        {
            var issuer = _configuration["Mfa:Issuer"] ?? "ApiGateway";
            // Standard otpauth URI format
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(username)}" +
                   $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1" +
                   $"&digits={CodeDigits}&period={TimeStepSeconds}";
        }

        /// <inheritdoc />
        public bool ValidateCode(string username, string code)
        {
            if (string.IsNullOrWhiteSpace(code) || code.Length != CodeDigits)
            {
                _logger.LogWarning("MFA validation failed for {Username}: invalid code format.", username);
                return false;
            }

            if (!_secrets.TryGetValue(username, out var secret))
            {
                _logger.LogWarning("MFA validation failed for {Username}: no secret registered.", username);
                return false;
            }

            var secretBytes = Base32Decode(secret);
            var currentStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / TimeStepSeconds;

            // Check current step and ±AllowedWindowSteps to handle clock skew
            for (var delta = -AllowedWindowSteps; delta <= AllowedWindowSteps; delta++)
            {
                var expected = ComputeTotp(secretBytes, currentStep + delta);
                if (expected == code)
                {
                    _logger.LogInformation("MFA code validated successfully for user: {Username}", username);
                    return true;
                }
            }

            _logger.LogWarning("MFA validation failed for {Username}: incorrect code.", username);
            return false;
        }

        // -----------------------------------------------------------------------
        // TOTP computation (RFC 6238 / HOTP RFC 4226)
        // -----------------------------------------------------------------------

        private static string ComputeTotp(byte[] secret, long counter)
        {
            // Counter as big-endian 8-byte array
            var counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counterBytes);

            using var hmac = new HMACSHA1(secret);
            var hash = hmac.ComputeHash(counterBytes);

            // Dynamic truncation
            var offset = hash[^1] & 0x0F;
            var truncated =
                ((hash[offset]     & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) <<  8) |
                 (hash[offset + 3] & 0xFF);

            var otp = truncated % (int)Math.Pow(10, CodeDigits);
            return otp.ToString().PadLeft(CodeDigits, '0');
        }

        // -----------------------------------------------------------------------
        // Base32 helpers (RFC 4648, no padding required for TOTP)
        // -----------------------------------------------------------------------

        private static readonly char[] Base32Alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

        private static string Base32Encode(byte[] data)
        {
            var sb = new StringBuilder();
            int buffer = data[0], next = 1, bitsLeft = 8;

            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xFF;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }

                int index = 0x1F & (buffer >> (bitsLeft - 5));
                bitsLeft -= 5;
                sb.Append(Base32Alphabet[index]);
            }

            return sb.ToString();
        }

        private static byte[] Base32Decode(string base32)
        {
            base32 = base32.TrimEnd('=').ToUpperInvariant();
            var output = new List<byte>();
            int buffer = 0, bitsLeft = 0;

            foreach (var c in base32)
            {
                var value = Array.IndexOf(Base32Alphabet, c);
                if (value < 0) continue;

                buffer <<= 5;
                buffer |= value;
                bitsLeft += 5;

                if (bitsLeft >= 8)
                {
                    output.Add((byte)(buffer >> (bitsLeft - 8)));
                    bitsLeft -= 8;
                }
            }

            return output.ToArray();
        }
    }
}
