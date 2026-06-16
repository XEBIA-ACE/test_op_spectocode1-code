"""Authentication package.

Exports the primary OAuth2 client surface.
"""

from src.auth.oauth_client import (
    FacebookOAuthProvider,
    GoogleOAuthProvider,
    OAuth2Client,
    OAuthConfig,
    OAuthProvider,
    OAuthProviderRegistry,
    UserProfile,
)

__all__ = [
    "OAuth2Client",
    "OAuthConfig",
    "OAuthProvider",
    "OAuthProviderRegistry",
    "UserProfile",
    "GoogleOAuthProvider",
    "FacebookOAuthProvider",
]
