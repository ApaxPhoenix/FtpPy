from dataclasses import dataclass
import base64


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

    user: str
    password: str
    auth: str = ""

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
        # Generate Basic auth header if not already provided
        if not self.auth:
            # Combine username and password with colon separator
            credentials = f"{self.user}:{self.password}"
            # Encode credentials in base64 as required by RFC 7617
            encoded = base64.b64encode(credentials.encode()).decode()
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

    key: str

    def __post_init__(self) -> None:
        """
        Initialize guest authentication configuration.

        For guest users, no additional processing is needed as the
        key attribute directly contains the X-Forwarded-Key value
        that describes this anonymous user.

        Returns:
            None
        """
        pass