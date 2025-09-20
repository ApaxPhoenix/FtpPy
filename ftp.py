from typing import (
    Optional,
    Dict,
    Callable,
    Tuple,
    TypeVar,
    Generic,
    Any,
    Awaitable,
)
from urllib.parse import urlparse
from aiohttp import web
from core import FtpServer, FtpClient
from auth import Basic
from config import Retry, Limits, Timeout
from settings import SSL

# Enhanced type definitions for improved type safety and clarity
T = TypeVar("T")
ClientType = TypeVar("ClientType", bound="FtpClient")
ServerType = TypeVar("ServerType", bound="FtpServer")
HandlerType = Callable[[web.Request], Awaitable[web.Response]]
ErrorHandlerType = Callable[[Optional[web.Request], web.Response], Awaitable[None]]
HookType = Callable[..., Awaitable[Any]]
AuthType = TypeVar("AuthType", bound=Basic)
ConfigType = TypeVar("ConfigType")
RouteResult = Tuple[HandlerType, Dict[str, Any]]
GenericFunction = TypeVar("GenericFunction", bound=Callable)


class FtpPy(Generic[ClientType, ServerType]):
    """
    Async FTP factory for creating client and server instances.

    Provides a unified configuration interface for FTP operations, handling connection
    parameters, SSL/TLS setup, and URL parsing. Creates both client and server instances
    that share the same configuration for consistent behavior across your application.

    Type Parameters:
        ClientType: The specific FTP client type to create
        ServerType: The specific FTP server type to create
    """

    def __init__(
        self,
        endpoint: str,
        auth: Optional[Basic] = None,
        limits: Optional[Limits] = None,
        retry: Optional[Retry] = None,
        timeout: Optional[Timeout] = None,
        ssl: Optional[SSL] = None,
        hooks: Optional[Dict[str, HookType]] = None,
        passive: bool = True,
        encoding: str = "utf-8",
    ) -> None:
        """Set up FTP connection parameters and shared configuration.

        This creates the foundation for FTP operations by parsing URLs, checking SSL settings,
        and setting up default configuration that gets shared between client and server instances.

        Args:
            endpoint: FTP URL like ftp://server.com or ftps://secure.com
            auth: Username and password for server access
            limits: How many connections and operations to allow
            retry: How to handle failed operations with backoff
            timeout: How long to wait for connections and operations
            ssl: SSL/TLS settings for secure connections
            hooks: Custom callbacks for monitoring and logging
            passive: Use passive mode for data connections (usually better)
            encoding: Text encoding for FTP protocol messages

        Raises:
            TypeError: If endpoint isn't a string
            ValueError: If endpoint scheme is wrong or SSL config is incomplete
        """
        if not isinstance(endpoint, str):
            raise TypeError("Endpoint must be a string.")

        # Parse the FTP URL to extract connection details
        url = urlparse(endpoint)

        if url.scheme not in {"ftp", "ftps"}:
            raise ValueError("Endpoint must start with 'ftp://' or 'ftps://'.")

        # Store connection info from URL
        self.endpoint: str = endpoint
        self.host: Optional[str] = url.hostname
        self.port: int = url.port or (21 if url.scheme == "ftp" else 990)
        self.secure: bool = url.scheme == "ftps"

        # Set up configuration with sensible defaults
        self.limits: Limits = limits or Limits()
        self.retry: Retry = retry or Retry()
        self.timeout: Timeout = timeout or Timeout()
        self.ssl: SSL = ssl or SSL()

        # Connection behavior settings
        self.passive: bool = passive
        self.encoding: str = encoding
        self.hooks: Dict[str, HookType] = hooks or {}
        self.auth: Optional[Basic] = auth

        # Make sure SSL is set up properly for secure connections
        if self.secure and self.ssl.verify and not self.ssl.context:
            raise ValueError(
                "SSL certificate verification required for secure FTPS connection"
            )

        # FTP only supports basic username/password auth
        if self.auth and not isinstance(self.auth, Basic):
            raise ValueError("FTP only supports Basic authentication")

    def server(self) -> "FtpServer":
        """Create an FTP server using the same configuration.

        Returns:
            FtpServer: Ready-to-start server instance
        """
        return FtpServer(
            endpoint=self.endpoint,
            auth=self.auth,
            limits=self.limits,
            retry=self.retry,
            timeout=self.timeout,
            ssl=self.ssl,
            hooks=self.hooks,
            passive=self.passive,
            encoding=self.encoding,
        )

    def client(self) -> "FtpClient":
        """Create an FTP client using the same configuration.

        Returns:
            FtpClient: Ready-to-connect client instance
        """
        return FtpClient(
            endpoint=self.endpoint,
            auth=self.auth,
            limits=self.limits,
            retry=self.retry,
            timeout=self.timeout,
            ssl=self.ssl,
            hooks=self.hooks,
            passive=self.passive,
            encoding=self.encoding,
        )
