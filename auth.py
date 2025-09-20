import warnings
from dataclasses import dataclass
import base64
from typing import TypeVar, Callable, Awaitable, Any, Optional

# Enhanced type definitions for improved type safety and clarity
T = TypeVar("T")
BasicAuthType = TypeVar("BasicAuthType", bound="Basic")
GuestAuthType = TypeVar("GuestAuthType", bound="Guest")
Username = str
Password = str
AuthHeader = str
GuestKey = str
CredentialsString = str
Base64EncodedString = str


@dataclass
class Basic:
    """
    Basic authentication configuration for HTTP requests.

    Implements HTTP Basic Authentication as defined in RFC 7617, which
    transmits credentials as a base64-encoded string in the Authorization
    header. This authentication method is simple but should only be used
    over HTTPS to prevent credential interception.

    Basic authentication is widely supported and commonly used for API
    endpoints, internal services, and systems where token-based auth
    is not available or necessary. The credentials are sent with every
    request, making it stateless but potentially less secure than
    token-based alternatives.

    Attributes:
        user: Username for authentication.
              Should be a valid identifier for the target service.
        password: Password or secret for authentication.
                 Should be kept secure and rotated regularly.
        auth: Complete authorization header string.
              Auto-generated if not provided during initialization.
    """

    user: Username
    password: Password
    auth: AuthHeader = ""

    def __post_init__(self) -> None:
        """
        Initialize basic authentication configuration.

        Automatically generates the Basic authentication header by encoding
        username:password in base64 format as required by RFC 7617.

        The generated header follows the format:
        Authorization: Basic <base64(username:password)>

        Returns:
            None
        """
        # Validate credentials before processing
        if not self.user.strip():
            raise ValueError("Username cannot be empty or whitespace")

        if not self.password.strip():
            raise ValueError("Password cannot be empty or whitespace")

        # Security warnings for potentially weak credentials
        if len(self.password) < 8:
            warnings.warn(
                "Password is shorter than 8 characters. "
                "Consider using a stronger password for better security."
            )

        if self.password.lower() in ['password', '123456', 'admin', 'root']:
            warnings.warn(
                "Password appears to be a common weak password. "
                "Use a strong, unique password for better security."
            )

        # Generate Basic auth header if not already provided
        if not self.auth:
            # Combine username and password with colon separator
            credentials: CredentialsString = f"{self.user}:{self.password}"
            # Encode credentials in base64 as required by RFC 7617
            encoded: Base64EncodedString = base64.b64encode(credentials.encode()).decode()
            # Create complete authorization header
            self.auth = f"Basic {encoded}"


@dataclass
class Guest:
    """
    Guest authentication configuration for anonymous HTTP requests.

    Implements anonymous/guest access patterns commonly used in APIs and
    web services that allow unauthenticated requests or provide public
    endpoints. This is useful for services that offer both authenticated
    and anonymous access tiers.

    Guest authentication typically uses forwarding headers to identify
    the source or nature of anonymous requests. The X-Forwarded-Key
    header is commonly used to provide a description or identifier
    for guest users without requiring full authentication.

    Attributes:
        key: X-Forwarded-Key header value that describes this guest user.
             Used to identify or describe anonymous requests without
             requiring authentication credentials.
    """

    key: GuestKey

    def __post_init__(self) -> None:
        """
        Initialize guest authentication configuration.

        Validates the guest key and provides warnings for potential
        security or identification issues with anonymous access.

        Returns:
            None
        """
        # Validate guest key
        if not self.key.strip():
            raise ValueError("Guest key cannot be empty or whitespace")

        # Security warnings for guest access
        if len(self.key) < 3:
            warnings.warn(
                "Guest key is very short. "
                "Consider using a more descriptive identifier."
            )

        if self.key.lower() in ['guest', 'anonymous', 'test', 'default']:
            warnings.warn(
                "Guest key appears to be a generic identifier. "
                "Consider using a more specific identifier for better tracking."
            )