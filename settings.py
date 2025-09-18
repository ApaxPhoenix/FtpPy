import ssl
import warnings
from dataclasses import dataclass
from typing import Optional, Union
from pathlib import Path


@dataclass
class SSL:
    """
    SSL/TLS configuration for HTTPS requests.

    Controls SSL certificate verification and encryption settings for secure
    HTTP connections. Provides flexible configuration options for various
    SSL/TLS scenarios including custom certificates, CA bundles, and cipher suites.

    SSL/TLS configuration is critical for secure communication and proper
    certificate validation. This class provides both simple verification
    control and advanced configuration options for enterprise environments
    requiring client certificates, custom CA bundles, or specific cipher suites.

    Attributes:
        verify: Whether to verify SSL certificates against trusted CAs.
               When False, connections are vulnerable to man-in-the-middle attacks
               but may be necessary for development or internal services with self-signed certs.
        cert: Path to client certificate file for mutual TLS authentication.
              Required for services that validate client identity through certificates.
        key: Path to client private key file for mutual TLS authentication.
             Must correspond to the certificate specified in 'cert' parameter.
        bundle: Path to custom CA bundle file for certificate verification.
                Useful for private CAs or additional trusted certificate authorities.
        ciphers: Allowed SSL cipher suites string for encryption control.
                Format follows OpenSSL cipher list format for fine-grained security control.
        context: Pre-configured SSL context object or False to disable verification.
                Allows complete control over SSL settings when default configuration insufficient.
    """

    verify: bool = True  # Whether to verify SSL certificates against trusted CAs
    cert: Optional[str] = None  # Path to client certificate file for mutual TLS
    key: Optional[str] = None  # Path to client private key file for mutual TLS
    bundle: Optional[str] = None  # Path to custom CA bundle file for verification
    ciphers: Optional[str] = None  # Allowed SSL cipher suites string
    context: Optional[Union[ssl.SSLContext, bool]] = None  # SSL context or False to disable

    def __post_init__(self) -> None:
        """
        Validate SSL configuration and initialize SSL context after initialization.

        Performs comprehensive validation of SSL parameters to ensure they are
        consistent and point to valid files. Creates an appropriate SSL context
        based on the configuration, handling various scenarios from simple
        verification control to complex enterprise setups.

        The method validates file paths, certificate/key pairs, and SSL context
        compatibility. It provides clear error messages for common configuration
        mistakes and security warnings for potentially unsafe configurations.

        Returns:
            None

        Raises:
            ValueError: If SSL configuration is invalid or inconsistent.
                       Includes specific error messages for different validation failures.
        """
        # Validate certificate and key file pairing
        # Both must be provided together for mutual TLS authentication
        if bool(self.cert) != bool(self.key):
            raise ValueError("Both certificate and key must be provided together for mutual TLS")

        # Validate certificate file existence and readability
        if self.cert:
            path = Path(self.cert)
            if not path.exists():
                raise ValueError(f"Certificate file not found: {self.cert}")
            if not path.is_file():
                raise ValueError(f"Certificate path is not a file: {self.cert}")

        # Validate private key file existence and readability
        if self.key:
            path = Path(self.key)
            if not path.exists():
                raise ValueError(f"Private key file not found: {self.key}")
            if not path.is_file():
                raise ValueError(f"Private key path is not a file: {self.key}")

        # Validate CA bundle file existence and readability
        if self.bundle:
            path = Path(self.bundle)
            if not path.exists():
                raise ValueError(f"CA bundle file not found: {self.bundle}")
            if not path.is_file():
                raise ValueError(f"CA bundle path is not a file: {self.bundle}")

        # Validate SSL context parameter type
        if self.context is not None and not isinstance(self.context, (ssl.SSLContext, bool)):
            raise ValueError("SSL context must be an SSLContext object, boolean, or None")

        # Security warning for disabled certificate verification
        if not self.verify:
            warnings.warn(
                "SSL certificate verification is disabled. "
                "This makes connections vulnerable to man-in-the-middle attacks. "
                "Only use this setting in development or trusted network environments.",
                UserWarning,
                stacklevel=3
            )

        # Warn about potentially incompatible configuration
        if self.context is False and any([self.cert, self.key, self.bundle, self.ciphers]):
            warnings.warn(
                "SSL context is explicitly disabled, but other SSL parameters are configured. "
                "These parameters will be ignored.",
                UserWarning,
                stacklevel=3
            )

        # Initialize SSL context based on validated configuration parameters
        # If context is already explicitly set, don't override it
        if self.context is not None:
            return

        # For simple verification control without advanced features
        if not any([self.cert, self.key, self.bundle, self.ciphers]):
            # Use None for default verification, False for disabled verification
            self.context = None if self.verify else False
            return

        # Create SSL context with secure default settings for advanced configuration
        try:
            ctx = ssl.create_default_context()
        except ssl.SSLError as error:
            raise ValueError(f"Failed to create default SSL context: {error}")

        # Configure certificate verification behavior
        if not self.verify:
            # Disable hostname checking and certificate verification
            # WARNING: This makes connections vulnerable to man-in-the-middle attacks
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Load client certificate and private key for mutual TLS authentication
        if self.cert and self.key:
            try:
                ctx.load_cert_chain(self.cert, self.key)
            except ssl.SSLError as error:
                raise ValueError(f"Failed to load client certificate chain: {error}")
            except FileNotFoundError as error:
                raise ValueError(f"Certificate or key file not found: {error}")
            except PermissionError as error:
                raise ValueError(f"Permission denied accessing certificate files: {error}")

        # Load custom CA bundle for certificate verification
        if self.bundle:
            try:
                ctx.load_verify_locations(cafile=self.bundle)
            except ssl.SSLError as error:
                raise ValueError(f"Failed to load CA bundle: {error}")
            except FileNotFoundError as error:
                raise ValueError(f"CA bundle file not found: {error}")
            except PermissionError as error:
                raise ValueError(f"Permission denied accessing CA bundle: {error}")

        # Configure allowed cipher suites for encryption control
        if self.ciphers:
            try:
                ctx.set_ciphers(self.ciphers)
            except ssl.SSLError as error:
                raise ValueError(f"Invalid cipher suite configuration: {error}")

        # Store the configured SSL context
        self.context = ctx