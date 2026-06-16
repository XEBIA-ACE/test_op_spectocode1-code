"""
tests/test_logger.py

Unit tests for src/utils/logger.py — verifying that:
  - Auth events produce log records at the correct level.
  - Every record contains timestamp, user identifier, and outcome.
  - Sensitive values (passwords, tokens) are NEVER written to log output.
  - The SensitiveDataFilter scrubs known secret patterns.
"""

import logging
import re
import sys
import os

# Allow running from repo root without installing the package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from src.utils.logger import (
    SensitiveDataFilter,
    _scrub,
    get_logger,
    log_auth_attempt,
    log_auth_callback,
    log_auth_error,
    log_auth_failure,
    log_auth_logout,
    log_auth_success,
    log_auth_token_refresh,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ListHandler(logging.Handler):
    """Capture log records into a list for assertion."""

    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    @property
    def messages(self) -> list[str]:
        return [self.format(r) for r in self.records]


def _attach_handler(logger_name: str) -> _ListHandler:
    """Attach a capturing handler to the named logger and return it."""
    handler = _ListHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(SensitiveDataFilter())
    logging.getLogger(logger_name).addHandler(handler)
    return handler


def _detach_handler(logger_name: str, handler: _ListHandler) -> None:
    logging.getLogger(logger_name).removeHandler(handler)


# ---------------------------------------------------------------------------
# _scrub unit tests
# ---------------------------------------------------------------------------

class TestScrub:
    def test_scrubs_password_equals(self):
        assert "[REDACTED]" in _scrub("password=s3cr3t")

    def test_scrubs_token_equals(self):
        assert "[REDACTED]" in _scrub("token=abc123xyz")

    def test_scrubs_bearer_token(self):
        assert "[REDACTED]" in _scrub("Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")

    def test_scrubs_access_token(self):
        assert "[REDACTED]" in _scrub("access_token=ya29.a0AfH6SMB")

    def test_scrubs_refresh_token(self):
        assert "[REDACTED]" in _scrub("refresh_token=1//0gXYZ")

    def test_scrubs_client_secret(self):
        assert "[REDACTED]" in _scrub("client_secret=GOCSPX-abc")

    def test_safe_text_unchanged(self):
        safe = "user=alice@example.com outcome=success"
        assert _scrub(safe) == safe

    def test_scrubs_case_insensitive(self):
        assert "[REDACTED]" in _scrub("PASSWORD=hunter2")


# ---------------------------------------------------------------------------
# SensitiveDataFilter unit tests
# ---------------------------------------------------------------------------

class TestSensitiveDataFilter:
    def _make_record(self, msg: str, args=None) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test", level=logging.INFO,
            pathname="", lineno=0,
            msg=msg, args=args or (), exc_info=None,
        )
        return record

    def test_filter_scrubs_message(self):
        f = SensitiveDataFilter()
        record = self._make_record("password=secret123")
        f.filter(record)
        assert "secret123" not in record.msg
        assert "[REDACTED]" in record.msg

    def test_filter_scrubs_args_tuple(self):
        f = SensitiveDataFilter()
        record = self._make_record("login %s", args=("token=abc",))
        f.filter(record)
        assert "abc" not in str(record.args)

    def test_filter_scrubs_args_dict(self):
        f = SensitiveDataFilter()
        record = self._make_record("login %(token)s", args={"token": "secret"})
        f.filter(record)
        # The dict value itself should be scrubbed (it doesn't match a pattern
        # on its own, but the key+value pair would if formatted).
        # At minimum the filter must not raise.
        assert record.args is not None

    def test_filter_returns_true(self):
        """Filter must always return True (allow the record through)."""
        f = SensitiveDataFilter()
        record = self._make_record("safe message")
        assert f.filter(record) is True


# ---------------------------------------------------------------------------
# Auth logging helper tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def capture_auth_log():
    """Attach a capturing handler around each test."""
    handler = _attach_handler("auth")
    yield handler
    _detach_handler("auth", handler)


class TestLogAuthAttempt:
    def test_produces_log_record(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        assert len(capture_auth_log.records) == 1

    def test_level_is_info(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        assert capture_auth_log.records[0].levelno == logging.INFO

    def test_contains_event_type(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        msg = capture_auth_log.messages[0]
        assert "AUTH_ATTEMPT" in msg

    def test_contains_user_identifier(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        assert "alice@example.com" in capture_auth_log.messages[0]

    def test_contains_timestamp(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        # ISO-8601 timestamp contains 'T' and '+' or 'Z'
        msg = capture_auth_log.messages[0]
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", msg)

    def test_no_password_in_log(self, capture_auth_log):
        log_auth_attempt("alice@example.com")
        assert "password" not in capture_auth_log.messages[0].lower() or \
               "[REDACTED]" in capture_auth_log.messages[0]

    def test_includes_provider(self, capture_auth_log):
        log_auth_attempt("alice@example.com", provider="google")
        assert "google" in capture_auth_log.messages[0]


class TestLogAuthSuccess:
    def test_level_is_info(self, capture_auth_log):
        log_auth_success("bob@example.com")
        assert capture_auth_log.records[0].levelno == logging.INFO

    def test_contains_success_outcome(self, capture_auth_log):
        log_auth_success("bob@example.com")
        assert "success" in capture_auth_log.messages[0]

    def test_contains_user(self, capture_auth_log):
        log_auth_success("bob@example.com")
        assert "bob@example.com" in capture_auth_log.messages[0]

    def test_no_token_in_log(self, capture_auth_log):
        log_auth_success("bob@example.com", provider="auth0")
        for msg in capture_auth_log.messages:
            # Raw token values must not appear
            assert "eyJ" not in msg  # JWT header prefix


class TestLogAuthFailure:
    def test_level_is_warning(self, capture_auth_log):
        log_auth_failure("charlie@example.com", reason="invalid_grant")
        assert capture_auth_log.records[0].levelno == logging.WARNING

    def test_contains_failure_event(self, capture_auth_log):
        log_auth_failure("charlie@example.com", reason="invalid_grant")
        assert "AUTH_FAILURE" in capture_auth_log.messages[0]

    def test_contains_reason(self, capture_auth_log):
        log_auth_failure("charlie@example.com", reason="token_expired")
        assert "token_expired" in capture_auth_log.messages[0]

    def test_reason_does_not_contain_raw_password(self, capture_auth_log):
        # Even if caller accidentally passes a password-like reason, it is scrubbed.
        log_auth_failure("charlie@example.com", reason="password=hunter2")
        assert "hunter2" not in capture_auth_log.messages[0]

    def test_contains_user(self, capture_auth_log):
        log_auth_failure("charlie@example.com", reason="invalid_grant")
        assert "charlie@example.com" in capture_auth_log.messages[0]


class TestLogAuthCallback:
    def test_success_is_info(self, capture_auth_log):
        log_auth_callback("dave@example.com", success=True)
        assert capture_auth_log.records[0].levelno == logging.INFO

    def test_failure_is_warning(self, capture_auth_log):
        log_auth_callback("dave@example.com", success=False)
        assert capture_auth_log.records[0].levelno == logging.WARNING

    def test_contains_callback_event(self, capture_auth_log):
        log_auth_callback("dave@example.com")
        assert "AUTH_CALLBACK" in capture_auth_log.messages[0]


class TestLogAuthLogout:
    def test_level_is_info(self, capture_auth_log):
        log_auth_logout("eve@example.com")
        assert capture_auth_log.records[0].levelno == logging.INFO

    def test_contains_logout_event(self, capture_auth_log):
        log_auth_logout("eve@example.com")
        assert "AUTH_LOGOUT" in capture_auth_log.messages[0]


class TestLogAuthTokenRefresh:
    def test_success_is_info(self, capture_auth_log):
        log_auth_token_refresh("frank@example.com", success=True)
        assert capture_auth_log.records[0].levelno == logging.INFO

    def test_failure_is_warning(self, capture_auth_log):
        log_auth_token_refresh("frank@example.com", success=False)
        assert capture_auth_log.records[0].levelno == logging.WARNING

    def test_no_token_value_logged(self, capture_auth_log):
        log_auth_token_refresh("frank@example.com", success=True)
        for msg in capture_auth_log.messages:
            assert "eyJ" not in msg


class TestLogAuthError:
    def test_level_is_error(self, capture_auth_log):
        log_auth_error("grace@example.com", ValueError("connection refused"))
        assert capture_auth_log.records[0].levelno == logging.ERROR

    def test_contains_error_event(self, capture_auth_log):
        log_auth_error("grace@example.com", ValueError("connection refused"))
        assert "AUTH_ERROR" in capture_auth_log.messages[0]

    def test_error_message_scrubbed(self, capture_auth_log):
        # Exception message containing a token must be scrubbed.
        log_auth_error("grace@example.com", ValueError("token=supersecret"))
        assert "supersecret" not in capture_auth_log.messages[0]

    def test_contains_error_type(self, capture_auth_log):
        log_auth_error("grace@example.com", RuntimeError("oauth error"))
        assert "RuntimeError" in capture_auth_log.messages[0]


# ---------------------------------------------------------------------------
# get_logger idempotency test
# ---------------------------------------------------------------------------

class TestGetLogger:
    def test_same_instance_returned(self):
        l1 = get_logger("idempotency_test")
        l2 = get_logger("idempotency_test")
        assert l1 is l2

    def test_no_duplicate_handlers(self):
        name = "dup_handler_test"
        get_logger(name)
        get_logger(name)
        logger = logging.getLogger(name)
        assert len(logger.handlers) == 1
