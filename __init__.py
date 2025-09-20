__version__ = "1.0.0"
__author__ = "Andrew Hernandez"
__email__ = "andromedeyz@hotmail.com"
__license__ = "MIT"
__description__ = "A high-performance async FTP client and server library for Python with connection pooling, SSL support, and automatic retry logic."
__url__ = "http://github.com/ApaxPhoenix/FtpPy"

# The main FtpPy class - your one-stop shop for creating FTP clients and servers
from .ftp import FtpPy

# The heart of FtpPy - these handle all your file transfer needs
from .core import (
    FtpServer,  # Run your own FTP server with a built-in web interface
    FtpClient,  # Connect to FTP servers with smart connection management
)

# Fine-tune how your FTP connections behave
from .config import (
    Timeout,  # Set how long to wait for connections and transfers
    Retry,  # Automatically retry failed operations with smart backoff
    Limits,  # Control connection pooling and resource usage
)

# Different ways to handle user authentication
from .auth import (
    Basic,  # Classic username and password login
    Guest,  # Allow anonymous access for public servers
)

# Keep your connections secure
from .settings import (
    SSL,  # Add encryption with SSL/TLS support
)

# Everything you can import and use
__all__ = [
    # The main class you'll work with
    "FtpPy",
    # Core functionality
    "FtpServer",
    "FtpClient",
    # Configuration options
    "Timeout",
    "Retry",
    "Limits",
    # Authentication types
    "Basic",
    "Guest",
    # Security settings
    "SSL",
    # Package info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__description__",
    "__url__",
]

# FTP response codes - what the server is trying to tell you
codes = {
    # 1xx - "Hold on, I'm working on it"
    110: "Restart marker reply",
    120: "Service ready in n minutes",
    125: "Data connection already open; transfer starting",
    150: "File status okay; about to open data connection",
    # 2xx - "Success! Everything went great"
    200: "Command okay",
    202: "Command not implemented, superfluous at this site",
    211: "System status, or system help reply",
    212: "Directory status",
    213: "File status",
    214: "Help message",
    215: "NAME system type",
    220: "Service ready for new user",
    221: "Service closing control connection",
    225: "Data connection open; no transfer in progress",
    226: "Closing data connection",
    227: "Entering Passive Mode",
    230: "User logged in, proceed",
    250: "Requested file action okay, completed",
    257: "PATHNAME created",
    # 3xx - "I need more info from you"
    331: "User name okay, need password",
    332: "Need account for login",
    350: "Requested file action pending further information",
    # 4xx - "Something's wrong, but we can try again"
    421: "Service not available, closing control connection",
    425: "Can't open data connection",
    426: "Connection closed; transfer aborted",
    450: "Requested file action not taken",
    451: "Requested action aborted: local error in processing",
    452: "Requested action not taken; insufficient storage space",
    # 5xx - "Nope, that's not going to work"
    500: "Syntax error, command unrecognized",
    501: "Syntax error in parameters or arguments",
    502: "Command not implemented",
    503: "Bad sequence of commands",
    504: "Command not implemented for that parameter",
    530: "Not logged in",
    532: "Need account for storing files",
    550: "Requested action not taken; file unavailable",
    551: "Requested action aborted: page type unknown",
    552: "Requested file action aborted; exceeded storage allocation",
    553: "Requested action not taken; file name not allowed",
}

# File types we recognize - helps with proper handling
types = {
    "text": "text/plain",
    "html": "text/html",
    "css": "text/css",
    "js": "application/javascript",
    "json": "application/json",
    "xml": "application/xml",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "tar": "application/x-tar",
    "gzip": "application/gzip",
    "jpg": "image/jpeg",
    "png": "image/png",
    "gif": "image/gif",
    "svg": "image/svg+xml",
    "mp4": "video/mp4",
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "binary": "application/octet-stream",
}

# Make sure you're running a modern Python version
import sys

if sys.version_info < (3, 9):
    raise RuntimeError("FtpPy needs Python 3.9 or newer to work properly")
