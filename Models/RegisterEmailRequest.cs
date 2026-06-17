using System.ComponentModel.DataAnnotations;

namespace ApiGateway.Models
{
    /// <summary>
    /// Request body for the POST /api/auth/register endpoint.
    /// </summary>
    public class RegisterEmailRequest
    {
        /// <summary>
        /// The email address the user wishes to register with.
        /// Must be a syntactically valid RFC 5322 address.
        /// </summary>
        [Required(ErrorMessage = "Email is required.")]
        public string Email { get; set; } = string.Empty;
    }
}
