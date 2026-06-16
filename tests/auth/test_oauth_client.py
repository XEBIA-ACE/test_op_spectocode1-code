"""
tests/auth/test_oauth_client.py

Unit tests for src/auth/oauth_client.py.

Covers:
  - authorization_url generation for Google and Facebook
  - code exchange (mocked HTTP)
  - user profile fetching (mocked HTTP)
  - OAuthClientFactory registration and error handling
  - Verification that no secrets/tokens appear in log output
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from src.auth.oauth_client import (
    FacebookOAuthProvider,
    GoogleOAuthProvider,
    OAuthClientFactory,
    OAuthUserProfile,
    OAuthProvider,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GOOGLE_ENV = {
    "GOOGLE_CLIENT_ID": "google-test-client-id",
    "GOOGLE_CLIENT_SECRET": "google-test-secret",
}

FACEBOOK_ENV = {
    "FACEBOOK_CLIENT_ID": "fb-test-client-id",
    "FACEBOOK_CLIENT_SECRET": "fb-test-secret",
}

REDIRECT_URI = "https://example.com/auth/callback"
STATE = "csrf-state-token"


@pytest.fixture()
def google_provider(monkeypatch):
    for k, v in GOOGLE_ENV.items():
        monkeypatch.setenv(k, v)
    return GoogleOAuthProvider()


@pytest.fixture()
def facebook_provider(monkeypatch):
    for k, v in FACEBOOK_ENV.items():
        monkeypatch.setenv(k, v)
    return FacebookOAuthProvider()


# ---------------------------------------------------------------------------
# Google – authorization_url
# ---------------------------------------------------------------------------


class TestGoogleAuthorizationUrl:
    def test_contains_client_id(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "google-test-client-id" in url

    def test_contains_redirect_uri(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "example.com" in url

    def test_contains_state_when_provided(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI, state=STATE)
        assert STATE in url

    def test_no_state_when_omitted(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "state" not in url

    def test_scope_includes_email(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "email" in url

    def test_response_type_code(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "response_type=code" in url

    def test_secret_not_in_url(self, google_provider):
        url = google_provider.authorization_url(REDIRECT_URI)
        assert "google-test-secret" not in url


# ---------------------------------------------------------------------------
# Google – exchange_code
# ---------------------------------------------------------------------------


class TestGoogleExchangeCode:
    def test_returns_token_data(self, google_provider):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "tok123", "token_type": "Bearer"}
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response) as mock_post:
            result = google_provider.exchange_code("auth-code", REDIRECT_URI)

        assert result["access_token"] == "tok123"
        mock_post.assert_called_once()

    def test_secret_not_logged(self, google_provider, caplog):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "tok123"}
        mock_response.raise_for_status = MagicMock()

        with caplog.at_level(logging.DEBUG, logger="src.auth.oauth_client"):
            with patch("requests.post", return_value=mock_response):
                google_provider.exchange_code("auth-code", REDIRECT_URI)

        for record in caplog.records:
            assert "google-test-secret" not in record.getMessage()

    def test_token_not_logged(self, google_provider, caplog):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "super-secret-token"}
        mock_response.raise_for_status = MagicMock()

        with caplog.at_level(logging.DEBUG, logger="src.auth.oauth_client"):
            with patch("requests.post", return_value=mock_response):
                google_provider.exchange_code("auth-code", REDIRECT_URI)

        for record in caplog.records:
            assert "super-secret-token" not in record.getMessage()


# ---------------------------------------------------------------------------
# Google – get_user_profile
# ---------------------------------------------------------------------------


class TestGoogleGetUserProfile:
    def test_returns_oauth_user_profile(self, google_provider):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "sub": "12345",
            "email": "user@example.com",
            "name": "Test User",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            profile = google_provider.get_user_profile("access-token")

        assert isinstance(profile, OAuthUserProfile)
        assert profile.uid == "12345"
        assert profile.email == "user@example.com"
        assert profile.name == "Test User"
        assert profile.provider == "google"

    def test_access_token_not_logged(self, google_provider, caplog):
        mock_response = MagicMock()
        mock_response.json.return_value = {"sub": "1", "email": "a@b.com", "name": "A"}
        mock_response.raise_for_status = MagicMock()

        with caplog.at_level(logging.DEBUG, logger="src.auth.oauth_client"):
            with patch("requests.get", return_value=mock_response):
                google_provider.get_user_profile("my-secret-access-token")

        for record in caplog.records:
            assert "my-secret-access-token" not in record.getMessage()


# ---------------------------------------------------------------------------
# Facebook – authorization_url
# ---------------------------------------------------------------------------


class TestFacebookAuthorizationUrl:
    def test_contains_client_id(self, facebook_provider):
        url = facebook_provider.authorization_url(REDIRECT_URI)
        assert "fb-test-client-id" in url

    def test_contains_state_when_provided(self, facebook_provider):
        url = facebook_provider.authorization_url(REDIRECT_URI, state=STATE)
        assert STATE in url

    def test_scope_includes_email(self, facebook_provider):
        url = facebook_provider.authorization_url(REDIRECT_URI)
        assert "email" in url

    def test_secret_not_in_url(self, facebook_provider):
        url = facebook_provider.authorization_url(REDIRECT_URI)
        assert "fb-test-secret" not in url


# ---------------------------------------------------------------------------
# Facebook – exchange_code
# ---------------------------------------------------------------------------


class TestFacebookExchangeCode:
    def test_returns_token_data(self, facebook_provider):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "fb-tok", "token_type": "bearer"}
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = facebook_provider.exchange_code("fb-code", REDIRECT_URI)

        assert result["access_token"] == "fb-tok"

    def test_secret_not_logged(self, facebook_provider, caplog):
        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "fb-tok"}
        mock_response.raise_for_status = MagicMock()

        with caplog.at_level(logging.DEBUG, logger="src.auth.oauth_client"):
            with patch("requests.post", return_value=mock_response):
                facebook_provider.exchange_code("fb-code", REDIRECT_URI)

        for record in caplog.records:
            assert "fb-test-secret" not in record.getMessage()


# ---------------------------------------------------------------------------
# Facebook – get_user_profile
# ---------------------------------------------------------------------------


class TestFacebookGetUserProfile:
    def test_returns_oauth_user_profile(self, facebook_provider):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "fb-uid-999",
            "email": "fbuser@example.com",
            "name": "FB User",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_response):
            profile = facebook_provider.get_user_profile("fb-access-token")

        assert isinstance(profile, OAuthUserProfile)
        assert profile.uid == "fb-uid-999"
        assert profile.email == "fbuser@example.com"
        assert profile.name == "FB User"
        assert profile.provider == "facebook"

    def test_access_token_not_logged(self, facebook_provider, caplog):
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "1", "email": "x@y.com", "name": "X"}
        mock_response.raise_for_status = MagicMock()

        with caplog.at_level(logging.DEBUG, logger="src.auth.oauth_client"):
            with patch("requests.get", return_value=mock_response):
                facebook_provider.get_user_profile("my-fb-secret-token")

        for record in caplog.records:
            assert "my-fb-secret-token" not in record.getMessage()


# ---------------------------------------------------------------------------
# OAuthClientFactory
# ---------------------------------------------------------------------------


class TestOAuthClientFactory:
    def test_get_google_provider(self, monkeypatch):
        for k, v in GOOGLE_ENV.items():
            monkeypatch.setenv(k, v)
        provider = OAuthClientFactory.get_provider("google")
        assert isinstance(provider, GoogleOAuthProvider)

    def test_get_facebook_provider(self, monkeypatch):
        for k, v in FACEBOOK_ENV.items():
            monkeypatch.setenv(k, v)
        provider = OAuthClientFactory.get_provider("facebook")
        assert isinstance(provider, FacebookOAuthProvider)

    def test_case_insensitive(self, monkeypatch):
        for k, v in GOOGLE_ENV.items():
            monkeypatch.setenv(k, v)
        provider = OAuthClientFactory.get_provider("Google")
        assert isinstance(provider, GoogleOAuthProvider)

    def test_unknown_provider_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown OAuth provider"):
            OAuthClientFactory.get_provider("twitter")

    def test_supported_providers_includes_google_and_facebook(self):
        supported = OAuthClientFactory.supported_providers()
        assert "google" in supported
        assert "facebook" in supported

    def test_register_new_provider(self, monkeypatch):
        class DummyProvider(OAuthProvider):
            PROVIDER_NAME = "dummy"

            def authorization_url(self, redirect_uri, state=None):
                return "https://dummy.example.com/auth"

            def exchange_code(self, code, redirect_uri):
                return {"access_token": "dummy-token"}

            def get_user_profile(self, access_token):
                return OAuthUserProfile(uid="1", email="a@b.com", name="A", provider="dummy")

        OAuthClientFactory.register("dummy", DummyProvider)
        provider = OAuthClientFactory.get_provider("dummy")
        assert isinstance(provider, DummyProvider)

    def test_register_non_provider_raises_type_error(self):
        with pytest.raises(TypeError):
            OAuthClientFactory.register("bad", object)  # type: ignore[arg-type]
