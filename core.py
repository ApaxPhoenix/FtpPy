import asyncio
import base64
import datetime
import fnmatch
import warnings
from functools import partial
from pathlib import Path
from typing import (
    Optional,
    Dict,
    Union,
    Callable,
    List,
    Tuple,
    TypeVar,
    Any,
    Awaitable,
)
from urllib.parse import urlparse
import aioftp
from aioftp import Client
from aiohttp import web
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


class FtpServer:
    """
    A solid async FTP server that comes with a web interface and handles errors gracefully.

    This sets up a full FTP server using aioftp, plus throws in HTTP endpoints so you can
    manage files through a REST API too. Works with both authenticated users and anonymous
    access, supports SSL/TLS, handles multiple connections, and won't crash when things go wrong.
    The web interface has CORS enabled so browser apps can use it easily.
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
        """Initialize the FTP server with all the bells and whistles.

        This constructor sets up both the FTP server and HTTP components. You can configure
        everything from authentication to SSL, connection limits, and custom event hooks.
        It's pretty flexible and should handle most production scenarios.

        Args:
            endpoint: Where to bind the server (like "ftp://localhost:2121")
            auth: Username/password if you want authentication, None for anonymous
            limits: How many connections to allow and other resource limits
            retry: Retry settings when things temporarily fail
            timeout: How long to wait for various operations before giving up
            ssl: SSL/TLS settings for encrypted connections
            hooks: Custom callbacks for events like startup, errors, requests
            passive: Use passive mode for data connections (usually what you want)
            encoding: Text encoding for the protocol (utf-8 is fine for most cases)
        """
        # Parse endpoint URL to get binding info
        url = urlparse(endpoint)
        self.endpoint: str = endpoint
        self.host: Optional[str] = url.hostname
        self.port: int = url.port or (21 if url.scheme == "ftp" else 990)
        self.secure: bool = url.scheme == "ftps"

        # Store config for server behavior
        self.limits: Limits = limits or Limits()
        self.retry: Retry = retry or Retry()
        self.timeout: Timeout = timeout or Timeout()
        self.ssl: SSL = ssl or SSL()
        self.passive: bool = passive
        self.encoding: str = encoding
        self.hooks: Dict[str, HookType] = hooks or {}
        self.auth: Optional[Basic] = auth

        # HTTP web interface components
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None

        # FTP server components
        self.server: Optional[aioftp.Server] = None
        self.path: Path = Path.home()  # Default to user's home directory

    async def start(self) -> aioftp.Server:
        """Fire up the FTP server and get it ready to handle connections.

        This does all the heavy lifting - sets up users and permissions, configures SSL
        if you're using it, and starts listening on the port. It also wraps the server
        dispatcher to handle common connection issues gracefully so random client
        disconnects won't crash your server.

        Returns:
            aioftp.Server: The server instance

        Raises:
            RuntimeError: When the server can't start (usually port conflicts)
        """
        try:
            # Build user list for aioftp.Server based on auth settings
            users = [
                aioftp.User(
                    login=self.auth.user if self.auth else "anonymous",
                    password=self.auth.password if self.auth else "",
                    base_path=str(self.path),
                    home_path="/",
                    permissions=[
                        aioftp.Permission("/", readable=True, writable=bool(self.auth))
                    ],
                )
            ]

            # Configure base server parameters
            kwargs: Dict[str, Any] = {
                "users": users,
                "path_io_factory": aioftp.PathIO,
                "path_timeout": self.timeout.connect,
                "idle_timeout": self.timeout.read,
                "socket_timeout": self.timeout.pool,
                "read_speed_limit": None,
                "write_speed_limit": None,
                "encoding": "utf-8-1",
                "maximum_connections": self.limits.connections,
            }

            # Handle SSL configuration for secure FTPS connections
            if self.secure:
                if self.ssl.context is False:
                    warnings.warn("SSL context is disabled but secure mode requested")
                elif self.ssl.context is not None:
                    kwargs["ssl"] = self.ssl.context
                else:
                    # Create default SSL context for server auth
                    import ssl

                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    if not self.ssl.verify:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    kwargs["ssl"] = context

            self.server = aioftp.Server(**kwargs)

            # Wrap server dispatcher to handle common connection errors gracefully
            default = self.server.dispatcher

            async def wrapper(*args, **kwargs):
                try:
                    return await default(*args, **kwargs)
                except (
                    ConnectionResetError,
                    UnicodeDecodeError,
                    asyncio.CancelledError,
                ) as error:
                    # These are expected errors from clients disconnecting abruptly
                    # or sending bad data - log but don't crash server
                    if "error" in self.hooks:
                        try:
                            await self.hooks["error"](error)
                        except Exception:
                            pass  # Hook failures shouldn't crash server
                    # Silently ignore these common connection issues
                    pass
                except Exception as error:
                    # Log unexpected errors but keep server running
                    if "error" in self.hooks:
                        try:
                            await self.hooks["error"](error)
                        except Exception:
                            pass

            self.server.dispatcher = wrapper

            # Start server listening on configured host and port
            await self.server.start(host=self.host or "127.0.0.1", port=self.port)

            # Run startup hook callback for custom initialization
            if "start" in self.hooks:
                try:
                    await self.hooks["start"](self.server)
                except Exception as error:
                    warnings.warn(f"Start hook failed: {error}")

            return self.server

        except OSError as error:
            # Handle common port binding errors with clear messages
            if "Address already in use" in str(error):
                raise RuntimeError(f"Port {self.port} is already in use")
            else:
                raise RuntimeError(f"Failed to bind to port {self.port}: {error}")
        except Exception as error:
            raise RuntimeError(f"Failed to start FTP server: {error}")

    async def stop(self) -> None:
        """Shut down the FTP server cleanly without leaving connections hanging.

        This closes all active connections, runs any cleanup hooks you've set up,
        and makes sure everything stops gracefully. It won't throw errors if the
        server is already stopped.

        Raises:
            RuntimeError: If there's an error during shutdown that can't be handled
        """
        if self.server:
            try:
                await self.server.close()

                # Run stop hook callback for custom cleanup
                if "stop" in self.hooks:
                    try:
                        await self.hooks["stop"](self.server)
                    except Exception as error:
                        warnings.warn(f"Stop hook failed: {error}")

            except Exception as error:
                warnings.warn(f"Error stopping FTP server: {error}")
                raise RuntimeError(f"Failed to stop FTP server: {error}")
            finally:
                self.server = None

    async def __aenter__(self) -> "FtpServer":
        """Start everything up when you use this in an async with statement.

        This is the context manager entry point. It starts both the FTP server
        and the web interface, then runs your connect hooks. Pretty convenient
        for managing server lifecycle automatically.

        Returns:
            FtpServer: This same instance, ready to handle requests

        Raises:
            RuntimeError: If either server fails to start up
        """
        try:
            await self.start()  # Start FTP server
            await self.web()  # Start web interface

            # Run connect hook with both server instances
            if "connect" in self.hooks:
                try:
                    info = {"ftp": self.server, "app": self.app}
                    await self.hooks["connect"](info)
                except Exception as error:
                    warnings.warn(f"Connect hook failed: {error}")

        except Exception as error:
            raise RuntimeError(f"Failed to start server: {error}")

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Clean shutdown when exiting the async with block.

        This stops both servers and cleans up all resources. Even if something
        goes wrong during shutdown, it'll try to clean up everything and won't
        leave zombie processes or open sockets lying around.
        """
        if self.server:
            await self.stop()

        # Clean up web server resources gracefully with error handling
        if self.site:
            try:
                await self.site.stop()
            except Exception as error:
                warnings.warn(f"Error stopping server site: {error}")
            finally:
                self.site = None

        if self.runner:
            try:
                await self.runner.cleanup()
            except Exception as error:
                warnings.warn(f"Error cleaning up server runner: {error}")
            finally:
                self.runner = None

        self.app = None

    async def web(self) -> None:
        """Start the HTTP web interface on port+1 for file management via REST API.

        This creates an aiohttp app with all the middleware and routes you need to
        upload, download, and delete files through HTTP requests. It automatically
        runs on your FTP port + 1, so if FTP is on 2121, the web interface will
        be on 2122. Includes CORS support so web browsers can use it.
        """
        self.app = web.Application(middlewares=[self.middleware, self.cors, self.log])

        # Set up HTTP routes for file operations
        self.app.router.add_get("/", self.stats)  # Server status
        self.app.router.add_get("/files/{path:.*}", self.get)  # File download
        self.app.router.add_post("/files/{path:.*}", self.post)  # File upload
        self.app.router.add_delete("/files/{path:.*}", self.delete)  # File deletion

        # Start web server runner
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        # Create TCP site on FTP port plus one for HTTP access
        self.site = web.TCPSite(
            self.runner,
            self.host or "127.0.0.1",
            self.port + 1,
            ssl_context=(
                self.ssl.context
                if (self.secure and self.ssl.context and self.ssl.context is not False)
                else None
            ),
        )

        await self.site.start()

    async def middleware(
        self, request: web.Request, handler: HandlerType
    ) -> web.Response:
        """Check authentication for HTTP requests (except the status endpoint).

        This middleware runs before every HTTP request and validates Basic Auth
        credentials if you've configured authentication. The status endpoint at "/"
        is always accessible without auth so monitoring tools can check if the
        server is alive.

        Args:
            request: The incoming HTTP request
            handler: The next middleware or route handler to call

        Returns:
            web.Response: Either a 401 if auth fails, or whatever the handler returns
        """
        if self.auth and request.path != "/":
            # Extract and validate Authorization header
            header = request.headers.get("Authorization", "")
            if not header.startswith("Basic "):
                return web.Response(
                    status=401, headers={"WWW-Authenticate": 'Basic realm="FTP Server"'}
                )

            try:
                # Decode base64 credentials and validate against config
                encoded = header.split(" ", 1)[1]
                decoded = base64.b64decode(encoded).decode("utf-8")
                username, password = decoded.split(":", 1)

                # Compare with configured authentication credentials
                if username != self.auth.user or password != self.auth.password:
                    return web.Response(status=401)
            except Exception:
                return web.Response(status=401)

        return await handler(request)

    async def cors(self, request: web.Request, handler: HandlerType) -> web.Response:
        """Add CORS headers so web browsers can actually use this API.

        Without CORS headers, browsers will block requests from web apps to this
        server due to same-origin policy. This middleware adds the necessary headers
        to allow cross-origin requests and handles preflight OPTIONS requests.

        Args:
            request: The HTTP request (used to check if it's a preflight OPTIONS)
            handler: Next handler in the middleware chain

        Returns:
            web.Response: The response with CORS headers added
        """
        response = (
            web.Response(status=200)
            if request.method == "OPTIONS"
            else await handler(request)
        )

        # Add CORS headers for cross-origin browser support
        response.headers.update(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization",
                "Access-Control-Max-Age": "86400",
            }
        )

        return response

    async def log(self, request: web.Request, handler: HandlerType) -> web.Response:
        """Log HTTP requests and run custom request hooks if you've set them up.

        This tracks request timing and calls your custom request hook with the
        request, response, and duration info. Useful for monitoring, analytics,
        or custom logging. Hook failures won't break the request processing.

        Args:
            request: The incoming HTTP request
            handler: Next handler in the middleware chain

        Returns:
            web.Response: Whatever the handler returns (logging is just a side effect)
        """
        start = asyncio.get_event_loop().time()

        try:
            # Process request through remaining handler chain
            response = await handler(request)
            duration = asyncio.get_event_loop().time() - start

            # Run custom request logging hook if configured
            if "request" in self.hooks:
                try:
                    await self.hooks["request"](request, response, duration)
                except Exception as error:
                    warnings.warn(f"Request hook failed: {error}")

            return response

        except Exception as error:
            raise

    async def get(self, request: web.Request) -> web.Response:
        """Download files through HTTP with efficient streaming for big files.

        This handles GET requests to download files. It streams the file content
        instead of loading everything into memory, so it can handle large files
        without eating up all your RAM. Includes proper security checks to prevent
        directory traversal attacks.

        Args:
            request: HTTP request with the file path in the URL

        Returns:
            web.Response: Streaming file download or error response
        """
        path = request.match_info["path"]

        try:
            # Build complete file path with security validation
            target = Path(self.path, path).resolve()
            if not str(target).startswith(str(self.path.resolve())):
                return web.Response(status=403, text="Access denied")

            if not target.exists():
                return web.Response(status=404, text="File not found")

            if target.is_dir():
                return web.Response(status=400, text="Path is a directory")

            # Create streaming response for efficient file download
            response = web.StreamResponse()
            response.headers.update(
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Disposition": f'attachment; filename="{target.name}"',
                    "Content-Length": str(target.stat().st_size),
                }
            )

            await response.prepare(request)

            # Stream file content in chunks to avoid memory issues
            with open(target, "rb") as file:
                while True:
                    chunk = file.read(8192)  # 8KB chunks
                    if not chunk:
                        break
                    await response.write(chunk)

            await response.write_eof()
            return response

        except Exception as error:
            return web.Response(status=500, text=str(error))

    async def post(self, request: web.Request) -> web.Response:
        """Handle file uploads through multipart form data.

        This processes POST requests with file uploads. It expects the file to be
        in a form field called "file" and handles multipart/form-data encoding.
        Creates parent directories as needed and includes the same security checks
        as the download endpoint.

        Args:
            request: HTTP request containing the uploaded file data

        Returns:
            web.Response: JSON response with upload status and file info
        """
        path = request.match_info["path"]

        try:
            # Parse multipart form data to extract uploaded file
            reader = await request.multipart()
            field = await reader.next()

            if not field or field.name != "file":
                return web.Response(status=400, text="Missing file field")

            # Build target file path with security validation
            target = Path(self.path, path).resolve()
            if not str(target).startswith(str(self.path.resolve())):
                return web.Response(status=403, text="Access denied")

            # Create parent directories if they don't exist
            target.parent.mkdir(parents=True, exist_ok=True)

            # Write uploaded file data to target location
            with open(target, "wb") as file:
                while True:
                    chunk = await field.read_chunk()
                    if not chunk:
                        break
                    file.write(chunk)

            return web.json_response(
                {
                    "status": "success",
                    "path": path,
                    "message": "File uploaded successfully",
                }
            )

        except Exception as error:
            return web.Response(status=500, text=str(error))

    async def delete(self, request: web.Request) -> web.Response:
        """Delete files or empty directories through HTTP DELETE requests.

        This handles file and directory deletion with the same security validations
        as other endpoints. For directories, it only removes empty ones (use rmdir
        semantics). For files, it removes them completely.

        Args:
            request: HTTP request with the path to delete

        Returns:
            web.Response: JSON response indicating success or failure
        """
        path = request.match_info["path"]

        try:
            # Build complete file path with security validation
            target = Path(self.path, path).resolve()
            if not str(target).startswith(str(self.path.resolve())):
                return web.Response(status=403, text="Access denied")

            if not target.exists():
                return web.Response(status=404, text="File not found")

            # Handle deletion based on file type
            if target.is_dir():
                target.rmdir()  # Only removes empty directories
            else:
                target.unlink()  # Remove file

            return web.json_response(
                {
                    "status": "success",
                    "path": path,
                    "message": "File deleted successfully",
                }
            )

        except Exception as error:
            return web.Response(status=500, text=str(error))

    async def stats(self, request: web.Request) -> web.Response:
        """Return server status and configuration info as JSON.

        This is the public endpoint that doesn't require authentication. It returns
        useful info about the server configuration, available endpoints, and current
        status. Handy for monitoring tools or just checking if everything is working.

        Args:
            request: HTTP request (not actually used but required by aiohttp)

        Returns:
            web.Response: JSON with server status and endpoint documentation
        """
        info = {
            "server": "FTP Server",
            "version": "1.0.0",
            "secure": self.secure,
            "path": str(self.path),
            "ports": {"ftp": self.port, "web": self.port + 1},
            "endpoints": {
                "files": "/files/{path}",
                "upload": "POST /files/{path}",
                "download": "GET /files/{path}",
                "delete": "DELETE /files/{path}",
            },
            "status": "active",
        }
        return web.json_response(info)


class FtpClient:
    """
    Fast async FTP client that handles connection pooling and tons of file operations.

    This client is built for serious file work - it manages multiple connections for
    speed, has smart retry logic when things go wrong, and includes everything you'd
    want for file management like batch uploads/downloads, directory syncing, backups,
    and checking file integrity. Works with regular FTP and secure FTPS, spreads the
    load across connections, and won't fall over when servers misbehave.
    """

    def __init__(
        self,
        endpoint: str,
        auth: Optional[Basic] = None,
        limits: Optional[Limits] = None,
        retry: Optional[Retry] = None,
        timeout: Optional[Timeout] = None,
        ssl: Optional[SSL] = None,
        hooks: Optional[Dict[str, Callable]] = None,
        passive: bool = True,
        encoding: str = "utf-8",
    ) -> None:
        """Set up the FTP client with all the config you need for real-world use.

        This builds the connection settings, SSL config, and behavior rules that'll
        be used for the main connection and the connection pool. Pretty much everything
        is configurable so you can tune it for your specific server and use case.

        Args:
            endpoint: FTP server URL like "ftp://myserver.com:2121" or "ftps://secure.com"
            auth: Username and password if the server needs them, None for anonymous
            limits: How many connections to pool and other resource constraints
            retry: Retry settings with backoff when operations fail temporarily
            timeout: How long to wait for connects, reads, and operations before giving up
            ssl: SSL/TLS config for secure connections (FTPS)
            hooks: Custom callbacks for events like connect, error, upload, etc.
            passive: Use passive mode for data connections (usually the right choice)
            encoding: Text encoding for the FTP protocol (utf-8 works for most servers)
        """
        # Parse endpoint URL to extract connection details
        url = urlparse(endpoint)
        self.endpoint = endpoint
        self.host = url.hostname
        self.port = url.port or (21 if url.scheme == "ftp" else 990)
        self.secure = url.scheme == "ftps"

        # Store config for client behavior
        self.limits = limits or Limits()
        self.retry = retry or Retry()
        self.timeout = timeout or Timeout()
        self.ssl = ssl or SSL()
        self.passive = passive
        self.encoding = encoding
        self.hooks = hooks or {}
        self.auth = auth

        # Connection state management
        self.connection: Optional[aioftp.Client] = None
        self.pool: List[aioftp.Client] = []  # Connection pool for concurrent operations

    async def __aenter__(self) -> Client:
        """Connect to the server and build a connection pool for fast concurrent operations.

        This creates the main connection plus additional pooled connections (up to your
        limit) so you can do multiple file operations at once. Each connection gets
        proper SSL setup and error handling so random network hiccups won't crash things.

        Returns:
            FtpClient: This same instance, ready to transfer files

        Raises:
            ConnectionError: If we can't connect, authenticate, or the server rejects us
        """
        if not self.connection:
            try:
                # Create main FTP client connection with SSL configuration
                self.connection = aioftp.Client(
                    encoding="utf-8-1",
                    ssl=(
                        self.ssl.context
                        if (self.secure and self.ssl.context)
                        else (True if self.secure else None)
                    ),
                )

                # Add error handling wrapper to main connection dispatcher
                if hasattr(self.connection, "dispatcher"):
                    original = self.connection.dispatcher

                    async def wrapper(*args, **kwargs):
                        try:
                            return await original(*args, **kwargs)
                        except (
                            ConnectionResetError,
                            UnicodeDecodeError,
                            asyncio.CancelledError,
                        ):
                            # Silently ignore common connection issues that don't require action
                            pass
                        except Exception as error:
                            warnings.warn(f"FTP client error: {error}")
                            if "error" in self.hooks:
                                try:
                                    await self.hooks["error"](error)
                                except Exception:
                                    pass  # Hook failures shouldn't crash client

                    self.connection.dispatcher = wrapper

                # Connect to server with timeout protection
                await asyncio.wait_for(
                    self.connection.connect(self.host, self.port),
                    timeout=self.timeout.connect,
                )

                # Configure passive mode after successful connection
                if hasattr(self.connection, "passive_mode"):
                    self.connection.passive_mode = self.passive

                # Authenticate with server using credentials or anonymous login
                if self.auth:
                    user = self.auth.user
                    password = self.auth.password
                    await self.connection.login(user, password)
                else:
                    await self.connection.login()  # Anonymous login

                # Run connect hook for custom initialization
                if "connect" in self.hooks:
                    try:
                        await self.hooks["connect"](self.connection)
                    except Exception as error:
                        warnings.warn(f"Connect hook failed: {error}")

            except asyncio.TimeoutError:
                raise ConnectionError(
                    f"Connection to {self.host}:{self.port} timed out"
                )
            except Exception as error:
                raise ConnectionError(f"Failed to connect to FTP server: {error}")

        # Build connection pool for concurrent operations
        for i in range(self.limits.connections):
            try:
                # Create pooled connection with same settings as main connection
                connection = aioftp.Client(
                    encoding="utf-8-1",
                    ssl=(
                        self.ssl.context
                        if self.secure and self.ssl.context is not None
                        else (True if self.secure else None)
                    ),
                )

                # Add error handling to pool connections
                if hasattr(connection, "dispatcher"):
                    original = connection.dispatcher

                    async def wrapper(*args, **kwargs):
                        try:
                            return await original(*args, **kwargs)
                        except (
                            ConnectionResetError,
                            UnicodeDecodeError,
                            asyncio.CancelledError,
                        ):
                            # Silently ignore common connection issues
                            pass
                        except Exception as error:
                            warnings.warn(f"FTP pool connection error: {error}")

                    connection.dispatcher = wrapper

                # Connect and authenticate pool connection
                await connection.connect(self.host, self.port)

                # Configure passive mode if supported by client
                if hasattr(connection, "passive_mode"):
                    connection.passive_mode = self.passive

                # Authenticate pool connection
                if self.auth:
                    user = self.auth.user
                    password = self.auth.password
                    await connection.login(user, password)
                else:
                    await connection.login()

                self.pool.append(connection)
            except Exception as error:
                warnings.warn(f"Pool connection {i} failed: {error}")

        return self.connection

    async def release(self, connection: aioftp.Client) -> None:
        """Put a connection back in the pool when you're done with it.

        This decrements the busy counter for load balancing purposes.
        Used internally after operations that grabbed a pooled connection.

        Args:
            connection: The connection to release back to the pool
        """
        if hasattr(connection, "busy"):
            setattr(connection, "busy", max(0, getattr(connection, "busy") - 1))

    async def sync(
        self, local: str, remote: str, direction: str = "up"
    ) -> Dict[str, bool]:
        """Keep directories in sync between local and remote locations.

        This is really handy for keeping backups, staging areas, or development
        environments synchronized. You can push local changes up, pull remote
        changes down, or do both directions to keep everything matched up.

        Args:
            local: Local directory path
            remote: Remote directory path
            direction: Which way to sync - 'up', 'down', or 'both'

        Returns:
            Dict mapping file paths to whether their sync succeeded

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        results = {}

        try:
            # Handle upload sync
            if direction in ("up", "both"):
                path = Path(local)
                if path.exists():
                    pairs = []
                    # Build upload pairs for all local files
                    for file in path.rglob("*"):
                        if file.is_file():
                            relative = file.relative_to(path)
                            target = str(Path(remote, relative))
                            pairs.append((str(file), target))

                    # Run batch upload
                    results.update(await self.batch(pairs))

            # Handle download sync
            if direction in ("down", "both"):
                files = await self.list(remote, deep=True)
                pairs = []
                # Build download pairs for all remote files
                for info in files:
                    if not info["dir"]:
                        source = info["path"]
                        relative = (
                            Path(source).relative_to(remote)
                            if remote != "."
                            else Path(source)
                        )
                        target = Path(local, relative)
                        pairs.append((source, str(target)))

                # Run batch download
                results.update(await self.fetch(pairs))

        except Exception as error:
            warnings.warn(f"Sync error: {error}")

        return results

    async def mirror(self, local: str, remote: str) -> Dict[str, bool]:
        """Make the remote directory an exact copy of the local directory.

        This completely wipes out what's on the remote side and replaces it
        with everything from the local directory. It's like a nuclear sync -
        very thorough but potentially destructive, so be careful.

        Args:
            local: Local directory to mirror
            remote: Remote directory that'll become an exact copy

        Returns:
            Dict mapping file paths to success status

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            # Clear remote directory completely
            try:
                await self.rmdir(remote, recursive=True)
            except:
                pass

            # Recreate remote directory structure
            await self.mkdir(remote, parents=True)

            # Upload all local files to create mirror
            return await self.sync(local, remote, "up")

        except Exception as error:
            warnings.warn(f"Mirror error: {error}")
            return {}

    async def backup(self, paths: List[str], target: str) -> Dict[str, bool]:
        """Create a timestamped backup of your important files and directories.

        This creates a backup directory with the current date and time, then
        copies everything you specified into it. Great for creating snapshots
        before making changes or just for regular backups.

        Args:
            paths: List of local paths to back up (files or directories)
            target: Remote directory where the backup will be stored

        Returns:
            Dict mapping each backed up path to success status

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        results = {}

        try:
            # Generate timestamped backup directory
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup = str(Path(target, f"backup_{timestamp}"))

            # Create backup directory structure
            await self.mkdir(backup, parents=True)

            # Process each path for backup
            for path in paths:
                location = Path(path)
                if location.exists():
                    if location.is_file():
                        # Handle single file backup
                        remote = str(Path(backup, location.name))
                        success = await self.upload(str(location), remote)
                        results[str(location)] = success
                    else:
                        # Handle directory backup
                        remote = str(Path(backup, location.name))
                        results.update(await self.sync(str(location), remote, "up"))

        except Exception as error:
            warnings.warn(f"Backup error: {error}")

        return results

    async def restore(self, backup: str, target: str) -> Dict[str, bool]:
        """Restore files from a remote backup to your local machine.

        Takes a backup directory on the remote server and downloads everything
        in it to your local target directory. Useful for recovering from backups
        or copying archived files back to your working environment.

        Args:
            backup: Remote backup directory path
            target: Local directory where files should be restored

        Returns:
            Dict mapping file paths to success status

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            # Make sure local target directory exists
            Path(target).mkdir(parents=True, exist_ok=True)

            # Download backup contents to target
            return await self.sync(target, backup, "down")

        except Exception as error:
            warnings.warn(f"Restore error: {error}")
            return {}

    async def verify(self, local: str, remote: str) -> Dict[str, bool]:
        """Check that your local and remote files match by comparing sizes.

        This doesn't do full content verification (that would be slow), but
        comparing file sizes catches most common sync issues. If sizes match,
        the files are probably identical. If they don't match, something
        definitely went wrong.

        Args:
            local: Local file or directory path
            remote: Remote file or directory path

        Returns:
            Dict mapping file paths to whether they match (True) or not (False)

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        results = {}

        try:
            path = Path(local)

            if path.is_file():
                # Verify single file size match
                if await self.exists(remote):
                    size = path.stat().st_size
                    remote_size = await self.size(remote)
                    results[local] = size == remote_size
                else:
                    results[local] = False
            else:
                # Verify directory contents
                for file in path.rglob("*"):
                    if file.is_file():
                        relative = file.relative_to(path)
                        location = str(Path(remote, relative))

                        if await self.exists(location):
                            size = file.stat().st_size
                            remote_size = await self.size(location)
                            results[str(file)] = size == remote_size
                        else:
                            results[str(file)] = False

        except Exception as error:
            warnings.warn(f"Verify error: {error}")

        return results

    async def search(
        self, pattern: str, path: str = "."
    ) -> List[Dict[str, Union[str, int, bool]]]:
        """Find files matching a pattern using wildcards.

        Uses fnmatch-style patterns where * matches anything and ? matches
        single characters. Searches recursively through the directory tree
        starting from the specified path.

        Args:
            pattern: Filename pattern with wildcards like "*.txt" or "test_*.py"
            path: Remote directory to start searching in

        Returns:
            List of file info dicts for files that match the pattern

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            # Get all files in directory tree
            files = await self.list(path, deep=True)
            matches = []

            # Filter files matching pattern
            for info in files:
                if fnmatch.fnmatch(info["name"], pattern):
                    matches.append(info)

            return matches

        except Exception as error:
            warnings.warn(f"Search error: {error}")
            return []

    async def stats(self) -> Dict[str, Union[str, int, bool]]:
        """Get status info about the client and its connections.

        Returns useful info about your connection state, how many pooled
        connections you have, how many are busy, and other configuration
        details. Handy for monitoring or debugging connection issues.

        Returns:
            Dict with client and connection pool statistics
        """
        active = sum(getattr(connection, "busy", 0) for connection in self.pool)

        return {
            "connected": self.connection is not None,
            "host": self.host,
            "port": self.port,
            "secure": self.secure,
            "pool": len(self.pool),
            "active": active,
            "encoding": self.encoding,
            "passive": self.passive,
        }

    async def __aexit__(self, type, value, trace) -> None:
        """Disconnect from the FTP server and clean up all pooled connections.

        This makes sure every connection gets closed properly and resources get freed,
        even if some individual disconnections fail. No hanging connections or
        zombie processes left behind.
        """
        if self.connection:
            try:
                await self.connection.quit()
            except Exception as error:
                warnings.warn(f"Error during FTP client cleanup: {error}")
            finally:
                self.connection = None

        # Close all pooled connections with individual error handling
        for connection in self.pool:
            try:
                await connection.quit()
            except Exception as error:
                warnings.warn(f"Pool cleanup error: {error}")
        self.pool.clear()

    async def upload(
        self,
        source: Union[str, Path],
        target: str,
        dirs: bool = True,
        replace: bool = True,
    ) -> bool:
        """Upload a file from your local machine to the FTP server with smart retries.

        This handles the whole upload process - creates remote directories if needed,
        deals with existing files based on your replace setting, and retries with
        exponential backoff if the upload fails temporarily.

        Args:
            source: Path to the local file you want to upload
            target: Where to put it on the remote server
            dirs: Create remote directories if they don't exist yet
            replace: Overwrite the file if it already exists remotely

        Returns:
            bool: True if the upload worked, False if it failed after all retries

        Raises:
            RuntimeError: If you forgot to use this in an async with block
            FileNotFoundError: If the local file doesn't exist
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        # Check local file exists
        file = Path(source)
        if not file.exists():
            raise FileNotFoundError(f"Local file not found: {source}")

        # Run upload hook
        if "upload" in self.hooks:
            try:
                await self.hooks["upload"](source, target)
            except Exception as error:
                warnings.warn(f"Upload hook failed: {error}")

        # Try upload with retries
        for attempt in range(self.retry.total + 1):
            try:
                # Create remote directories if needed
                if dirs:
                    folder = str(Path(target).parent)
                    if folder not in (".", "/"):
                        try:
                            await self.connection.make_directory(folder, parents=True)
                        except aioftp.StatusCodeError as error:
                            if "550" not in str(error.received_codes):
                                warnings.warn(
                                    f"Could not create directory {folder}: {error}"
                                )

                # Check if we should replace existing files
                if not replace:
                    try:
                        await self.connection.stat(target)
                        warnings.warn(f"File {target} exists and replace disabled")
                        return False
                    except aioftp.StatusCodeError:
                        pass  # File doesn't exist, continue

                # Upload the file
                await asyncio.wait_for(
                    self.connection.upload(str(file), target), timeout=self.timeout.pool
                )

                return True

            except asyncio.TimeoutError:
                if attempt < self.retry.total:
                    warnings.warn(
                        f"Upload timeout, retrying... (attempt {attempt + 1}/{self.retry.total})"
                    )
                    delay = self.retry.backoff * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    warnings.warn(
                        f"Upload failed: timeout after {self.retry.total} attempts"
                    )
                    break

            except aioftp.StatusCodeError as error:
                if attempt < self.retry.total and any(
                    code in str(error.received_codes) for code in ["4", "5"]
                ):
                    warnings.warn(
                        f"Upload failed with error {error.received_codes}, retrying..."
                    )
                    delay = self.retry.backoff * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    warnings.warn(f"Upload failed with FTP error: {error}")
                    break

            except Exception as error:
                warnings.warn(f"Upload failed with unexpected error: {error}")
                break

        return False

    async def download(
        self,
        source: str,
        target: Union[str, Path],
        dirs: bool = True,
        replace: bool = True,
    ) -> bool:
        """Download a file from the FTP server to your local machine with retry logic.

        Handles the complete download process including creating local directories,
        checking file replacement policies, and retrying failed downloads with
        increasing delays between attempts.

        Args:
            source: Path to the file on the remote server
            target: Where to save it locally
            dirs: Create local directories if they don't exist
            replace: Overwrite local file if it already exists

        Returns:
            bool: True if download succeeded, False if it failed after all retries

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        file = Path(target)

        # Run download hook
        if "download" in self.hooks:
            try:
                await self.hooks["download"](source, target)
            except Exception as error:
                warnings.warn(f"Download hook failed: {error}")

        # Create local directories if needed
        if dirs and file.parent != Path("."):
            file.parent.mkdir(parents=True, exist_ok=True)

        # Check file replacement policy
        if not replace and file.exists():
            warnings.warn(f"Local file {target} exists and replace disabled")
            return False

        # Try download with retries
        for attempt in range(self.retry.total + 1):
            try:
                await asyncio.wait_for(
                    self.connection.download(source, str(file)),
                    timeout=self.timeout.pool,
                )

                return True

            except asyncio.TimeoutError:
                if attempt < self.retry.total:
                    warnings.warn(
                        f"Download timeout, retrying... (attempt {attempt + 1}/{self.retry.total})"
                    )
                    delay = self.retry.backoff * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    warnings.warn(
                        f"Download failed: timeout after {self.retry.total} attempts"
                    )
                    break

            except aioftp.StatusCodeError as error:
                if attempt < self.retry.total and any(
                    code in str(error.received_codes) for code in ["4", "5"]
                ):
                    warnings.warn(
                        f"Download failed with error {error.received_codes}, retrying..."
                    )
                    delay = self.retry.backoff * (2**attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    warnings.warn(f"Download failed with FTP error: {error}")
                    break

            except Exception as error:
                warnings.warn(f"Download failed with unexpected error: {error}")
                break

        return False

    async def batch(
        self,
        pairs: List[Tuple[Union[str, Path], str]],
        dirs: bool = True,
        replace: bool = True,
        limit: int = 5,
    ) -> Dict[str, bool]:
        """Upload a bunch of files at once using concurrent connections.

        This is where the connection pool really shines - it can upload multiple
        files simultaneously instead of doing them one by one. Uses a semaphore
        to control how many uploads run at the same time so you don't overwhelm
        the server or your network.

        Args:
            pairs: List of (local_path, remote_path) tuples for each file
            dirs: Create remote directories as needed
            replace: Overwrite existing remote files
            limit: Maximum number of simultaneous uploads (don't go crazy)

        Returns:
            Dict mapping each source path to whether its upload succeeded

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        # Control how many uploads run at once
        semaphore = asyncio.Semaphore(limit)
        results = {}

        async def wrapper(source, target):
            """Upload one file with concurrency control."""
            async with semaphore:
                success = await self.upload(source, target, dirs, replace)
                results[str(source)] = success

        # Start all uploads
        tasks = [partial(wrapper, source, target)() for source, target in pairs]
        await asyncio.gather(*tasks, return_exceptions=True)

        return results

    async def fetch(
        self,
        pairs: List[Tuple[str, Union[str, Path]]],
        dirs: bool = True,
        replace: bool = True,
        limit: int = 5,
    ) -> Dict[str, bool]:
        """Download multiple files concurrently using the connection pool.

        Same idea as batch uploads but in reverse - downloads several files at once
        instead of waiting for each one to finish. Great for grabbing lots of files
        quickly without blocking on each individual transfer.

        Args:
            pairs: List of (remote_path, local_path) tuples for each file
            dirs: Create local directories as needed
            replace: Overwrite existing local files
            limit: Maximum simultaneous downloads (be reasonable)

        Returns:
            Dict mapping each remote source path to success status

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        # Control concurrent downloads
        semaphore = asyncio.Semaphore(limit)
        results = {}

        async def wrapper(source, target):
            """Download one file with concurrency control."""
            async with semaphore:
                success = await self.download(source, target, dirs, replace)
                results[source] = success

        # Start all downloads
        tasks = [partial(wrapper, source, target)() for source, target in pairs]
        await asyncio.gather(*tasks, return_exceptions=True)

        return results

    async def list(
        self,
        path: str = ".",
        deep: bool = False,
    ) -> List[Dict[str, Union[str, int, bool]]]:
        """Get a listing of files and directories on the server.

        This gives you file info like names, sizes, modification times, and whether
        each entry is a file or directory. With deep=True it'll recurse into
        subdirectories and give you everything in the tree.

        Args:
            path: Remote directory to list (defaults to current directory)
            deep: Recurse into subdirectories for a complete tree listing

        Returns:
            List of dicts with file info (path, name, size, is_dir, etc.)

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            files = [
                {
                    "path": str(filepath),
                    "name": filepath.name,
                    "dir": metadata["type"] == "dir",
                    "size": metadata.get("size", 0),
                    "modified": metadata.get("modify", ""),
                }
                async for filepath, metadata in self.connection.list(
                    path, recursive=deep
                )
            ]
            return files

        except aioftp.StatusCodeError as error:
            warnings.warn(f"Directory listing failed: {error}")
            return []
        except Exception as error:
            warnings.warn(f"Unexpected error during listing: {error}")
            return []

    async def remove(self, path: str) -> bool:
        """Delete a file or directory on the server.

        Simple deletion - works for both files and directories. For directories,
        this might fail if they're not empty (depends on the server), so you
        might want to use rmdir with recursive=True for reliable directory removal.

        Args:
            path: Remote path to delete

        Returns:
            bool: True if deletion worked, False if it failed

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.remove(path)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"File deletion failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during deletion: {error}")
            return False

    async def mkdir(self, path: str, parents: bool = True) -> bool:
        """Create a directory on the server.

        With parents=True (the default), this will create any missing parent
        directories along the way, like mkdir -p on Unix. Pretty handy when
        you need to create nested directory structures.

        Args:
            path: Remote directory path to create
            parents: Create parent directories if they don't exist

        Returns:
            bool: True if directory creation succeeded, False otherwise

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.make_directory(path, parents=parents)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Directory creation failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during directory creation: {error}")
            return False

    async def exists(self, path: str) -> bool:
        """Check if a file or directory exists on the server.

        Simple existence check - tries to stat the path and returns True if it
        works, False if the path doesn't exist or we get an error accessing it.

        Args:
            path: Remote path to check

        Returns:
            bool: True if the path exists, False if not (or if we can't access it)

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.stat(path)
            return True
        except aioftp.StatusCodeError:
            return False
        except Exception as error:
            warnings.warn(f"Error checking path existence: {error}")
            return False

    async def size(self, path: str) -> Optional[int]:
        """Get the size of a file on the server.

        Returns the file size in bytes, or None if the file doesn't exist or
        we can't get the size info. Only works for files, not directories.

        Args:
            path: Remote file path to check

        Returns:
            File size in bytes, or None if file doesn't exist or error occurred

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            info = await self.connection.stat(path)
            return info.get("size", 0)
        except aioftp.StatusCodeError:
            return None
        except Exception as error:
            warnings.warn(f"Error getting file size: {error}")
            return None

    async def move(self, old: str, new: str) -> bool:
        """Move a file or directory to a new location on the server.

        This is basically a rename that can also move files between directories.
        Works for both files and directories. The destination path should include
        the new filename, not just the target directory.

        Args:
            old: Current remote path
            new: New remote path (full path including filename)

        Returns:
            bool: True if the move succeeded, False if it failed

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.rename(old, new)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Move failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during move: {error}")
            return False

    async def rename(self, old: str, new: str) -> bool:
        """Rename a file or directory on the server.

        This is the same as move() - FTP doesn't really distinguish between
        renaming and moving. The new name should be the complete path, not
        just the new filename.

        Args:
            old: Current remote path
            new: New remote path (complete path)

        Returns:
            bool: True if rename succeeded, False otherwise

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.rename(old, new)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Rename failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during rename: {error}")
            return False

    async def copy(self, source: str, target: str) -> bool:
        """Copy a file on the server by downloading and re-uploading it.

        Since FTP doesn't have a native copy command, this downloads the file
        to a temporary location and then uploads it to the new path. Not the
        most efficient for large files, but it gets the job done.

        Args:
            source: Source remote path
            target: Target remote path

        Returns:
            bool: True if copy succeeded, False if either download or upload failed

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            # Download to temp file then upload to new location
            import tempfile

            with tempfile.NamedTemporaryFile() as temp:
                success = await self.download(source, temp.name, replace=True)
                if not success:
                    return False

                return await self.upload(temp.name, target, replace=True)
        except Exception as error:
            warnings.warn(f"Copy operation failed: {error}")
            return False

    async def chmod(self, path: str, mode: str) -> bool:
        """Change file permissions using the SITE CHMOD command.

        Not all FTP servers support this, but many Unix-based servers do.
        The mode should be in octal format like '755' or '644'. Whether
        this actually works depends on your server.

        Args:
            path: Remote file path to change permissions for
            mode: Permission mode like '755', '644', etc.

        Returns:
            bool: True if chmod succeeded, False if server doesn't support it or failed

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            command = f"SITE CHMOD {mode} {path}"
            await self.connection.command(command)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Chmod failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during chmod: {error}")
            return False

    async def pwd(self) -> Optional[str]:
        """Get the current working directory path.

        Returns the full path of where you currently are on the server.
        Useful for keeping track of your location or building relative paths.

        Returns:
            Current working directory path, or None if we couldn't get it

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            path = await self.connection.get_current_directory()
            return str(path)
        except Exception as error:
            warnings.warn(f"Error getting current directory: {error}")
            return None

    async def cd(self, path: str) -> bool:
        """Change the current working directory.

        Moves to a different directory on the server. Subsequent relative paths
        will be relative to this new location. Can use '..' to go up a level
        or absolute paths starting with '/'.

        Args:
            path: Remote directory path to change to

        Returns:
            bool: True if directory change succeeded, False if path doesn't exist

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            await self.connection.change_directory(path)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Directory change failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during directory change: {error}")
            return False

    async def rmdir(self, path: str, recursive: bool = False) -> bool:
        """Remove a directory, optionally deleting everything inside it first.

        With recursive=False, this only removes empty directories. With
        recursive=True, it deletes all files and subdirectories first,
        then removes the directory itself. Be careful with recursive=True!

        Args:
            path: Remote directory path to remove
            recursive: Delete all contents first (dangerous but thorough)

        Returns:
            bool: True if removal succeeded, False otherwise

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            if recursive:
                # Get all files and remove them first
                files = await self.list(path, deep=True)
                for info in reversed(files):
                    item = info["path"]
                    if info["dir"]:
                        await self.connection.remove_directory(item)
                    else:
                        await self.connection.remove(item)

            await self.connection.remove_directory(path)
            return True
        except aioftp.StatusCodeError as error:
            warnings.warn(f"Directory removal failed: {error}")
            return False
        except Exception as error:
            warnings.warn(f"Unexpected error during directory removal: {error}")
            return False

    async def metadata(self, path: str) -> Optional[Dict[str, Union[str, int, bool]]]:
        """Get detailed file or directory information.

        Returns all the metadata the server provides about a file or directory -
        size, type, permissions, modification time, owner, group, etc. What's
        available depends on the server, but you'll always get the basics.

        Args:
            path: Remote path to get information about

        Returns:
            Dict with all available metadata, or None if path doesn't exist

        Raises:
            RuntimeError: If you forgot to use this in an async with block
        """
        if not self.connection:
            raise RuntimeError("Client not initialized. Use within 'async with' block.")

        try:
            info = await self.connection.stat(path)
            return {
                "path": path,
                "name": Path(path).name,
                "size": info.get("size", 0),
                "type": info.get("type", "file"),
                "permissions": info.get("unix.mode", ""),
                "modified": info.get("modify", ""),
                "owner": info.get("unix.owner", ""),
                "group": info.get("unix.group", ""),
            }
        except Exception as error:
            warnings.warn(f"Error getting metadata: {error}")
            return None
