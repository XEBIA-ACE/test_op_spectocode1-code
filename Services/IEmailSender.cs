namespace ApiGateway.Services
{
    /// <summary>
    /// Abstraction for sending emails. Implementations can be swapped for real SMTP,
    /// SendGrid, SES, etc. without changing controller logic.
    /// </summary>
    public interface IEmailSender
    {
        /// <summary>
        /// Sends a verification email to the specified address.
        /// </summary>
        /// <param name="toEmail">Recipient email address.</param>
        /// <param name="subject">Email subject line.</param>
        /// <param name="body">Email body content (plain text or HTML).</param>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the underlying mail transport is unavailable or rejects the message.
        /// </exception>
        Task SendEmailAsync(string toEmail, string subject, string body);
    }
}
