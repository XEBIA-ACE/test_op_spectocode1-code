"""
src/utils/logger.py

Secure, audit-grade logging utilities for authentication events.

Design principles (per constitution.md and spec.md):
  - Passwords, tokens, and other secrets are NEVER written to any log.
  - Every auth log record includes: ISO-8601 timestamp, user identifier,
    event type, and outcome/result code.
  - A SensitiveDataFilter is attached to every handler to act as a
    last-resort safety net against accidental credential leakage.
  - Log format is structured (JSON-like via LogRecord extras) so that
    downstream SIEM / audit tools can parse records reliably.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex patterns for values that must never appear in log output.
# Extend this list as new secret patterns are identified.
_SENSITIVE_PATTERNS: list[re.Pattern] = [
    re.compile(r"password\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"passwd\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"secret\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"token\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"access_token\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"refresh_token\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"client_secret\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"authorization\s*:\s*\S+", re.IGNORECASE),
    re.compile(r"bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    # Generic key=value where key contains "pass", "pwd", "secret", "token"
    re.compile(r'["\']?(pass(?:word)?|pwd|secret|token)["\']?\s*[=:]\s*["\']?\S+["\']?', re.IGNORECASE),
]

_REDACTED = "[REDACTED]"

# Auth event type constants — use these in call sites for consistency.
AUTH_ATTEMPT = "AUTH_ATTEMPT"
AUTH_SUCCESS = "AUTH_SUCCESS"
AUTH_FAILURE = "AUTH_FAILURE"
AUTH_CALLBACK = "AUTH_CALLBACK"
AUTH_LOGOUT   = "AUTH_LOGOUT"
AUTH_TOKEN_REFRESH = "AUTH_TOKEN_REFRESH"
AUTH_ERROR    = "AUTH_ERROR"


# ---------------------------------------------------------------------------
# Sensitive-data filter
# ---------------------------------------------------------------------------

class SensitiveDataFilter(logging.Filter):
    """
    A logging.Filter that scrubs known sensitive patterns from every log
    record's message before it is emitted.

    Attach this filter to handlers (not just loggers) so that it fires
    regardless of which logger produced the record.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        # Sanitise the formatted message in-place.
        record.msg = _scrub(str(record.msg))
        # Also sanitise any positional args that will be interpolated later.
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: _scrub(str(v)) for k, v in record.args.items()}
            else:
                record.args = tuple(_scrub(str(a)) for a in record.args)
        return True  # always allow the record through (after scrubbing)


def _scrub(text: str) -> str:
    """Replace all sensitive patterns in *text* with ``[REDACTED]``."""
    for pattern in _SENSITIVE_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

def get_logger(name: str = "auth") -> logging.Logger:
    """
    Return a named logger pre-configured with:
      - A StreamHandler (stdout) with the SensitiveDataFilter attached.
      - An audit-friendly format that includes timestamp and logger name.

    Call this once per module::

        logger = get_logger(__name__)

    The returned logger is idempotent — calling it multiple times with the
    same *name* returns the same logger without duplicating handlers.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        # Already configured; return as-is to avoid duplicate handlers.
        return logger

    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)

    # Structured format: timestamp | level | logger | message
    fmt = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    formatter = logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")
    handler.setFormatter(formatter)

    # Attach the sensitive-data filter to the handler (last-resort guard).
    handler.addFilter(SensitiveDataFilter())

    logger.addHandler(handler)
    # Prevent propagation to the root logger to avoid double-logging.
    logger.propagate = False

    return logger


# ---------------------------------------------------------------------------
# Auth-specific logging helpers
# ---------------------------------------------------------------------------

# Module-level auth logger used by the helpers below.
_auth_logger = get_logger("auth")


def log_auth_attempt(user_identifier: str, provider: Optional[str] = None) -> None:
    """
    Log the initiation of an authentication attempt.

    Args:
        user_identifier: A non-sensitive identifier for the user, e.g. an
                         email address or username.  Must NOT be a password
                         or secret token.
        provider:        Optional OAuth provider name (e.g. "google", "auth0").
    """
    _auth_logger.info(
        "event=%s | user=%s | provider=%s | timestamp=%s",
        AUTH_ATTEMPT,
        _scrub(user_identifier),
        provider or "unknown",
        _utcnow(),
    )


def log_auth_success(user_identifier: str, provider: Optional[str] = None) -> None:
    """
    Log a successful authentication.

    Args:
        user_identifier: Non-sensitive user identifier (email / username / sub).
        provider:        OAuth provider that validated the credentials.
    """
    _auth_logger.info(
        "event=%s | user=%s | provider=%s | outcome=success | timestamp=%s",
        AUTH_SUCCESS,
        _scrub(user_identifier),
        provider or "unknown",
        _utcnow(),
    )


def log_auth_failure(
    user_identifier: str,
    reason: str,
    provider: Optional[str] = None,
) -> None:
    """
    Log a failed authentication attempt.

    Args:
        user_identifier: Non-sensitive user identifier (may be empty/unknown
                         if the request did not supply one).
        reason:          Human-readable failure reason that does NOT contain
                         credentials (e.g. "invalid_grant", "token_expired").
        provider:        OAuth provider involved, if known.
    """
    _auth_logger.warning(
        "event=%s | user=%s | provider=%s | outcome=failure | reason=%s | timestamp=%s",
        AUTH_FAILURE,
        _scrub(user_identifier),
        provider or "unknown",
        _scrub(reason),
        _utcnow(),
    )


def log_auth_callback(
    user_identifier: str,
    provider: Optional[str] = None,
    success: bool = True,
) -> None:
    """
    Log the result of an OAuth 2.0 callback (redirect) event.

    Args:
        user_identifier: Non-sensitive user identifier resolved from the
                         OAuth provider's response.
        provider:        OAuth provider name.
        success:         Whether the callback was processed successfully.
    """
    outcome = "success" if success else "failure"
    level = logging.INFO if success else logging.WARNING
    _auth_logger.log(
        level,
        "event=%s | user=%s | provider=%s | outcome=%s | timestamp=%s",
        AUTH_CALLBACK,
        _scrub(user_identifier),
        provider or "unknown",
        outcome,
        _utcnow(),
    )


def log_auth_logout(user_identifier: str, provider: Optional[str] = None) -> None:
    """
    Log a user logout event.

    Args:
        user_identifier: Non-sensitive user identifier.
        provider:        OAuth provider, if applicable.
    """
    _auth_logger.info(
        "event=%s | user=%s | provider=%s | timestamp=%s",
        AUTH_LOGOUT,
        _scrub(user_identifier),
        provider or "unknown",
        _utcnow(),
    )


def log_auth_token_refresh(
    user_identifier: str,
    provider: Optional[str] = None,
    success: bool = True,
) -> None:
    """
    Log a token-refresh event (access token renewed via refresh token).

    The refresh token value itself is NEVER logged.

    Args:
        user_identifier: Non-sensitive user identifier.
        provider:        OAuth provider name.
        success:         Whether the refresh succeeded.
    """
    outcome = "success" if success else "failure"
    level = logging.INFO if success else logging.WARNING
    _auth_logger.log(
        level,
        "event=%s | user=%s | provider=%s | outcome=%s | timestamp=%s",
        AUTH_TOKEN_REFRESH,
        _scrub(user_identifier),
        provider or "unknown",
        outcome,
        _utcnow(),
    )


def log_auth_error(
    user_identifier: str,
    error: Exception,
    provider: Optional[str] = None,
) -> None:
    """
    Log an unexpected error during an authentication flow.

    The exception message is scrubbed before logging to prevent accidental
    credential leakage via exception strings.

    Args:
        user_identifier: Non-sensitive user identifier (may be "unknown").
        error:           The exception that was raised.
        provider:        OAuth provider involved, if known.
    """
    _auth_logger.error(
        "event=%s | user=%s | provider=%s | error_type=%s | error=%s | timestamp=%s",
        AUTH_ERROR,
        _scrub(user_identifier),
        provider or "unknown",
        type(error).__name__,
        _scrub(str(error)),
        _utcnow(),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()
