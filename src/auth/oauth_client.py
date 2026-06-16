"""
Generic OAuth2 client handler supporting Google and Facebook providers.

Design principles (per constitution.md and spec.md):
- No secrets or credentials are hardcoded; all are read from environment variables.
- Clean separation of provider-specific details from shared flow logic.
- Extensible: add a new provider by subclassing OAuthProvider and registering it.
- Minimum required scopes are requested from each provider.
- No sensitive data is logged or exposed in exceptions.
"""

from __future__ import annotations

import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import requests  # type: ignore


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class OAuthConfig:
    """Runtime configuration for a single OAuth2 provider.

    All values are sourced from environment variables at instantiation time;
    nothing is hardcoded.
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    authorization_url: str
    token_url: str
    userinfo_url: str
    scopes: list[str]


@dataclass
class UserProfile:
    """Normalised user profile returned after a successful OAuth2 flow."""

    provider: str
    provider_user_id: str
    email: str | None
    name: str | None
    # Raw payload kept for callers that need provider-specific fields.
    raw: dict[str, Any]


# ---------------------------------------------------------------------------
# Abstract base provider
# ---------------------------------------------------------------------------


class OAuthProvider(ABC):
    """Abstract base class for an OAuth2 provider.

    Subclass this to add support for a new provider.  The only requirements
    are:
      - ``name``  – unique slug used as a registry key.
      - ``build_config()`` – return an ``OAuthConfig`` populated from env vars.
      - ``parse_profile()`` – map the raw userinfo payload to ``UserProfile``.
    """

    #: Unique provider slug, e.g. "google" or "facebook".
    name: str

    @abstractmethod
    def build_config(self) -> OAuthConfig:
        """Return provider configuration sourced from environment variables."""

    @abstractmethod
    def parse_profile(self, raw: dict[str, Any]) -> UserProfile:
        """Map a raw userinfo API response to a normalised ``UserProfile``."""


# ---------------------------------------------------------------------------
# Google provider
# ---------------------------------------------------------------------------


class GoogleOAuthProvider(OAuthProvider):
    """OAuth2 provider implementation for Google.

    Required environment variables:
        GOOGLE_CLIENT_ID
        GOOGLE_CLIENT_SECRET
        GOOGLE_REDIRECT_URI
    """

    name = "google"

    def build_config(self) -> OAuthConfig:
        client_id = os.environ.get("GOOGLE_CLIENT_ID")
        client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
        redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI")

        if not client_id or not client_secret or not redirect_uri:
            raise EnvironmentError(
                "Google OAuth2 requires GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "
                "and GOOGLE_REDIRECT_URI to be set as environment variables."
            )

        return OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token",
            userinfo_url="https://openidconnect.googleapis.com/v1/userinfo",
            # Minimum scopes: openid + email + profile (name/picture).
            scopes=["openid", "email", "profile"],
        )

    def parse_profile(self, raw: dict[str, Any]) -> UserProfile:
        return UserProfile(
            provider=self.name,
            provider_user_id=str(raw.get("sub", "")),
            email=raw.get("email"),
            name=raw.get("name"),
            raw=raw,
        )


# ---------------------------------------------------------------------------
# Facebook provider
# ---------------------------------------------------------------------------


class FacebookOAuthProvider(OAuthProvider):
    """OAuth2 provider implementation for Facebook.

    Required environment variables:
        FACEBOOK_CLIENT_ID
        FACEBOOK_CLIENT_SECRET
        FACEBOOK_REDIRECT_URI
    """

    name = "facebook"

    def build_config(self) -> OAuthConfig:
        client_id = os.environ.get("FACEBOOK_CLIENT_ID")
        client_secret = os.environ.get("FACEBOOK_CLIENT_SECRET")
        redirect_uri = os.environ.get("FACEBOOK_REDIRECT_URI")

        if not client_id or not client_secret or not redirect_uri:
            raise EnvironmentError(
                "Facebook OAuth2 requires FACEBOOK_CLIENT_ID, FACEBOOK_CLIENT_SECRET, "
                "and FACEBOOK_REDIRECT_URI to be set as environment variables."
            )

        return OAuthConfig(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            authorization_url="https://www.facebook.com/v19.0/dialog/oauth",
            token_url="https://graph.facebook.com/v19.0/oauth/access_token",
            # Facebook Graph API userinfo endpoint; fields are explicit to
            # request only the minimum data required (GDPR / spec AC #6).
            userinfo_url="https://graph.facebook.com/me?fields=id,name,email",
            scopes=["email", "public_profile"],
        )

    def parse_profile(self, raw: dict[str, Any]) -> UserProfile:
        return UserProfile(
            provider=self.name,
            provider_user_id=str(raw.get("id", "")),
            email=raw.get("email"),
            name=raw.get("name"),
            raw=raw,
        )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

# Built-in providers registered by default.
_BUILT_IN_PROVIDERS: list[type[OAuthProvider]] = [
    GoogleOAuthProvider,
    FacebookOAuthProvider,
]


class OAuthProviderRegistry:
    """Maintains a mapping of provider name → provider instance.

    Callers can register additional providers at runtime to extend support
    beyond Google and Facebook without modifying this module.
    """

    def __init__(self) -> None:
        self._providers: dict[str, OAuthProvider] = {}
        for cls in _BUILT_IN_PROVIDERS:
            self.register(cls())

    def register(self, provider: OAuthProvider) -> None:
        """Register a provider instance under its ``name`` slug."""
        self._providers[provider.name] = provider

    def get(self, name: str) -> OAuthProvider:
        """Return the provider for *name*, raising ``KeyError`` if unknown."""
        try:
            return self._providers[name]
        except KeyError:
            raise KeyError(
                f"Unknown OAuth2 provider '{name}'. "
                f"Registered providers: {list(self._providers)}"
            )

    @property
    def available(self) -> list[str]:
        """Return a list of registered provider names."""
        return list(self._providers)


# ---------------------------------------------------------------------------
# Core OAuth2 client
# ---------------------------------------------------------------------------


class OAuth2Client:
    """Generic OAuth2 authorization-code-flow client.

    Usage example::

        client = OAuth2Client()

        # 1. Redirect the user to the provider's authorization page.
        auth_url, state = client.get_authorization_url("google")
        # Store `state` in the session for CSRF validation.

        # 2. After the provider redirects back with ?code=...&state=...
        profile = client.fetch_user_profile("google", code=code, state=state,
                                             expected_state=session_state)

    The client is stateless; callers are responsible for persisting the
    ``state`` token between the initiation and callback steps.
    """

    def __init__(self, registry: OAuthProviderRegistry | None = None) -> None:
        self._registry = registry or OAuthProviderRegistry()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_authorization_url(self, provider_name: str) -> tuple[str, str]:
        """Build the provider's authorization URL and a CSRF state token.

        Args:
            provider_name: Registered provider slug, e.g. ``"google"``.

        Returns:
            A ``(authorization_url, state)`` tuple.  The caller **must**
            store ``state`` (e.g. in the session) and verify it on callback
            to prevent CSRF attacks.
        """
        provider = self._registry.get(provider_name)
        config = provider.build_config()

        # Cryptographically random state token for CSRF protection (OWASP).
        state = secrets.token_urlsafe(32)

        params = {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes),
            "state": state,
        }

        authorization_url = f"{config.authorization_url}?{urlencode(params)}"
        return authorization_url, state

    def fetch_user_profile(
        self,
        provider_name: str,
        *,
        code: str,
        state: str,
        expected_state: str,
    ) -> UserProfile:
        """Complete the OAuth2 flow and return the authenticated user's profile.

        Args:
            provider_name:  Registered provider slug.
            code:           Authorization code received from the provider callback.
            state:          State value received from the provider callback.
            expected_state: State value stored in the session at flow initiation.

        Returns:
            A normalised ``UserProfile``.

        Raises:
            ValueError: If the ``state`` parameter does not match
                        ``expected_state`` (CSRF guard).
            requests.HTTPError: If any HTTP request to the provider fails.
        """
        # CSRF guard – compare in constant time to avoid timing attacks.
        if not secrets.compare_digest(state, expected_state):
            raise ValueError(
                "OAuth2 state mismatch: possible CSRF attack detected."
            )

        provider = self._registry.get(provider_name)
        config = provider.build_config()

        access_token = self._exchange_code_for_token(code, config)
        raw_profile = self._fetch_userinfo(access_token, config)
        return provider.parse_profile(raw_profile)

    def register_provider(self, provider: OAuthProvider) -> None:
        """Register a custom provider at runtime for extensibility.

        Args:
            provider: An instance of a class that subclasses ``OAuthProvider``.
        """
        self._registry.register(provider)

    @property
    def available_providers(self) -> list[str]:
        """Return the names of all currently registered providers."""
        return self._registry.available

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _exchange_code_for_token(self, code: str, config: OAuthConfig) -> str:
        """Exchange an authorization code for an access token.

        Credentials are sent in the POST body (not as query params) to avoid
        accidental logging of secrets in server access logs.
        """
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
            "client_id": config.client_id,
            "client_secret": config.client_secret,
        }

        response = requests.post(
            config.token_url,
            data=payload,
            timeout=10,
        )
        # Raise for 4xx/5xx without leaking the response body (may contain tokens).
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise requests.HTTPError(
                f"Token exchange failed for provider (HTTP {response.status_code})."
            ) from exc

        token_data: dict[str, Any] = response.json()
        access_token: str | None = token_data.get("access_token")
        if not access_token:
            raise ValueError("Provider token response did not include an access_token.")
        return access_token

    def _fetch_userinfo(self, access_token: str, config: OAuthConfig) -> dict[str, Any]:
        """Retrieve the user's profile from the provider's userinfo endpoint."""
        response = requests.get(
            config.userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise requests.HTTPError(
                f"Userinfo request failed (HTTP {response.status_code})."
            ) from exc

        return response.json()  # type: ignore[no-any-return]
