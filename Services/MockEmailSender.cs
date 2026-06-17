namespace ApiGateway.Services
{
    /// <summary>
    /// No-op / console-logging email sender used during development and integration tests.
    /// Replace with a real SMTP or transactional-email provider in production.
    /// </summary>
    public class MockEmailSender : IEmailSender
    {
        private readonly ILogger<MockEmailSender> _logger;

        public MockEmailSender(ILogger<MockEmailSender> logger)
        {
            _logger = logger;
        }

        /// <inheritdoc />
        public Task SendEmailAsync(string toEmail, string subject, string body)
        {
            // TODO: Replace with real email transport (SMTP, SendGrid, AWS SES, etc.)
            _logger.LogInformation(
                "[MockEmailSender] Would send email to {ToEmail} | Subject: {Subject}",
                toEmail, subject);

            return Task.CompletedTask;
        }
    }
}
