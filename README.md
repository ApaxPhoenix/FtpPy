# FtpPy
**FtpPy** is a high-performance, asynchronous FTP client and server library for Python. Built with modern async/await patterns, it excels in file transfer operations, backup automation, and directory synchronization with support for both FTP and secure FTPS protocols.

## Core Features
* **Async/Await Support** - Native async programming with connection pooling
* **Client & Server** - Unified factory for creating both FTP clients and servers
* **Connection Pooling** - Multiple concurrent connections for faster transfers
* **Smart Retry Logic** - Exponential backoff for transient failures
* **SSL/TLS Support** - Secure FTPS with custom certificate handling
* **Batch Operations** - Concurrent uploads and downloads
* **Directory Sync** - Bidirectional synchronization with verification
* **Web Interface** - HTTP REST API for file management
* **Backup & Restore** - Timestamped backup creation and recovery
* **Authentication** - Basic auth with guest/anonymous access

## Quick Start Guide
This example demonstrates the basic usage pattern. The library uses async context managers to ensure proper resource cleanup and connection management:
```python
import asyncio
from ftppy import FtpPy
from auth import Basic
from config import Timeout, Retry, Limits

async def main():
    # Configure client with endpoint and authentication
    ftp = FtpPy(
        endpoint='ftp://localhost:2121',
        auth=Basic('username', 'password'),
        timeout=Timeout(connect=5.0, read=30.0),
        retry=Retry(total=3),
        limits=Limits(connections=10)
    )
    
    # Use client for file operations
    async with ftp.client() as client:
        # Upload a file
        success = await client.upload('document.txt', 'remote.txt')
        print(f"Upload success: {success}")
        
        # List directory contents
        files = await client.list('/uploads')
        for metadata in files:
            print(f"{metadata['name']} - {metadata['size']} bytes")

asyncio.run(main())
```
**How it works:** Creates an FtpPy factory with endpoint configuration, sets up authentication and connection limits, creates a client instance that manages connection pooling automatically, and ensures proper cleanup through async context managers.

## File Operations

### Upload Files
Upload files from local filesystem to remote FTP server with automatic retry and directory creation:
```python
from ftppy import FtpPy
from auth import Basic

async with FtpPy('ftp://server.com', auth=Basic('user', 'pass')).client() as client:
    # Basic file upload
    success = await client.upload('document.pdf', '/uploads/document.pdf')
    
    # Upload with directory creation
    success = await client.upload(
        'report.txt', 
        '/reports/2024/january/report.txt',
        dirs=True  # Creates intermediate directories
    )
    
    # Upload without overwriting existing files
    success = await client.upload(
        'backup.zip',
        '/backups/backup.zip',
        replace=False  # Skip if file exists
    )
```

### Download Files
Download files from remote server to local filesystem with retry logic:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Basic download
    success = await client.download('/data/report.csv', 'report.csv')
    
    # Download with local directory creation
    success = await client.download(
        '/archives/data.zip',
        'backups/archives/data.zip',
        dirs=True  # Creates local directories
    )
    
    # Download without overwriting
    success = await client.download(
        '/important.txt',
        'important.txt',
        replace=False
    )
```

### Batch Operations
Perform multiple file operations concurrently using connection pooling:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Batch upload multiple files
    uploads = [
        ('file1.txt', '/uploads/file1.txt'),
        ('file2.pdf', '/uploads/file2.pdf'),
        ('data.csv', '/uploads/data.csv')
    ]
    results = await client.batch(uploads, limit=5)  # Max 5 concurrent uploads
    
    # Batch download multiple files
    downloads = [
        ('/downloads/report1.txt', 'reports/report1.txt'),
        ('/downloads/report2.txt', 'reports/report2.txt'),
        ('/downloads/data.json', 'data/data.json')
    ]
    results = await client.fetch(downloads, limit=3)  # Max 3 concurrent downloads
    
    # Check results
    for path, success in results.items():
        print(f"{path}: {'Success' if success else 'Failed'}")
```

### Directory Management
Navigate and manage directories on the remote server:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Create directories
    success = await client.mkdir('/new/folder/structure', parents=True)
    
    # Change working directory
    success = await client.cd('/uploads')
    path = await client.pwd()  # Get current directory
    print(f"Current directory: {path}")
    
    # List directory contents
    files = await client.list('/data', deep=True)  # Recursive listing
    for metadata in files:
        type = "DIR" if metadata['dir'] else "FILE"
        print(f"{type}: {metadata['name']} ({metadata['size']} bytes)")
    
    # Remove files and directories
    success = await client.remove('/old/file.txt')
    success = await client.rmdir('/empty/folder')
    success = await client.rmdir('/full/folder', recursive=True)  # Delete all contents
```

### File Manipulation
Manipulate files directly on the remote server:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Move and rename files
    success = await client.move('/old/location.txt', '/new/location.txt')
    success = await client.rename('/file.txt', '/renamed.txt')
    
    # Copy files (downloads then uploads)
    success = await client.copy('/source.txt', '/destination.txt')
    
    # Check file existence and get information
    exists = await client.exists('/data/report.csv')
    size = await client.size('/data/report.csv')
    metadata = await client.metadata('/data/report.csv')
    
    if metadata:
        print(f"File: {metadata['name']}")
        print(f"Size: {metadata['size']} bytes")
        print(f"Modified: {metadata['modified']}")
        print(f"Permissions: {metadata['permissions']}")
    
    # Change permissions (if server supports SITE CHMOD)
    success = await client.chmod('/script.sh', '755')
```

### Directory Synchronization
Keep local and remote directories synchronized with verification:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Upload sync (local to remote)
    results = await client.sync('/local/folder', '/remote/folder', 'up')
    
    # Download sync (remote to local)  
    results = await client.sync('/local/folder', '/remote/folder', 'down')
    
    # Bidirectional sync
    results = await client.sync('/local/folder', '/remote/folder', 'both')
    
    # Check sync results
    for path, success in results.items():
        print(f"{path}: {'Synced' if success else 'Failed'}")
    
    # Verify sync integrity by comparing file sizes
    check = await client.verify('/local/folder', '/remote/folder')
    for path, matches in check.items():
        print(f"{path}: {'Match' if matches else 'Mismatch'}")
```

### Backup and Restore
Create timestamped backups and restore from them:
```python
from ftppy import FtpPy

async with FtpPy('ftp://backup.server.com').client() as client:
    # Create backup of important files
    sources = ['/important/data', '/config/files', '/logs/current.log']
    results = await client.backup(sources, '/backups/daily')
    
    # Mirror entire directory (destructive sync)
    results = await client.mirror('/local/website', '/remote/website')
    
    # Restore from backup
    results = await client.restore('/backups/daily/backup_20241225_143022', '/restore')
    
    # Check backup results
    for path, success in results.items():
        status = 'Backed up' if success else 'Failed'
        print(f"{path}: {status}")
```

### File Search
Search for files using pattern matching:
```python
from ftppy import FtpPy

async with FtpPy('ftp://server.com').client() as client:
    # Search for files by pattern
    logs = await client.search('*.log', '/var/logs')
    configs = await client.search('config.*', '/etc')
    backups = await client.search('backup_2024*.zip', '/backups')
    
    # Display search results
    for metadata in logs:
        print(f"Log file: {metadata['path']} ({metadata['size']} bytes)")
    
    # Get client statistics
    stats = await client.stats()
    print(f"Connected to {stats['host']}:{stats['port']}")
    print(f"Pool: {stats['pool']} connections, {stats['active']} active")
    print(f"Secure: {stats['secure']}, Passive: {stats['passive']}")
```

## Configuration

### Authentication Setup
Configure different authentication methods for server access:
```python
from ftppy import FtpPy
from auth import Basic, Guest

# Basic username/password authentication
auth = Basic('myuser', 'mypassword')
ftp = FtpPy('ftp://server.com', auth=auth)

# Guest/anonymous access with identifier
guest = Guest('webapp-client-v1.0')
ftp = FtpPy('ftp://public.server.com', auth=guest)

# Anonymous access (no authentication)
ftp = FtpPy('ftp://anonymous.server.com')  # auth=None is default
```

### Connection Limits
Control connection pooling and resource usage:
```python
from ftppy import FtpPy
from config import Limits

# Configure connection pool limits
limits = Limits(
    connections=20,  # Maximum total connections
    keepalive=5,     # Connections to keep alive when idle
    host=10          # Maximum connections per host
)
ftp = FtpPy('ftp://server.com', limits=limits)
```

### Timeout Configuration
Set timeouts for different phases of FTP operations:
```python
from ftppy import FtpPy
from config import Timeout

# Configure operation timeouts
timeout = Timeout(
    connect=10.0,  # Connection establishment timeout
    read=60.0,     # Data transfer read timeout
    write=30.0,    # Data transfer write timeout
    pool=120.0     # Total operation timeout
)
ftp = FtpPy('ftp://server.com', timeout=timeout)
```

### Retry Configuration
Configure automatic retry behavior for failed operations:
```python
from ftppy import FtpPy
from config import Retry

# Configure retry with exponential backoff
retry = Retry(
    total=5,                    # Maximum retry attempts
    backoff=2.0,               # Backoff multiplier (delay = backoff * 2^attempt)
    status=[421, 450, 500, 502] # FTP status codes that trigger retries
)
ftp = FtpPy('ftp://server.com', retry=retry)
```

### SSL/TLS Configuration
Configure secure FTPS connections with SSL certificate handling:
```python
from ftppy import FtpPy
from settings import SSL
from auth import Basic

# Basic secure FTPS with default verification
ssl = SSL(verify=True)
ftp = FtpPy('ftps://secure.server.com', ssl=ssl, auth=Basic('user', 'pass'))

# FTPS with client certificate authentication
ssl = SSL(
    verify=True,
    cert='/path/to/client.crt',    # Client certificate
    key='/path/to/client.key',     # Client private key
    bundle='/path/to/ca.crt'       # Custom CA bundle
)
ftp = FtpPy('ftps://server.com', ssl=ssl)

# FTPS with custom cipher configuration
ssl = SSL(
    verify=True,
    ciphers='ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5'
)
ftp = FtpPy('ftps://server.com', ssl=ssl)

# Disable SSL verification (not recommended for production)
ssl = SSL(verify=False)
ftp = FtpPy('ftps://server.com', ssl=ssl)
```

## Server Operations

### FTP Server Setup
Create and manage FTP servers with web interface:
```python
from ftppy import FtpPy
from auth import Basic
from config import Limits, Timeout
from settings import SSL

# Basic FTP server
ftp = FtpPy('ftp://localhost:2121', auth=Basic('admin', 'secret'))

async with ftp.server() as server:
    print("FTP server running on port 2121")
    print("Web interface available on port 2122")
    
    # Server runs until context exits
    await asyncio.sleep(3600)  # Run for 1 hour

# Secure FTPS server with SSL
ssl = SSL(cert='/path/to/server.crt', key='/path/to/server.key')
ftp = FtpPy(
    'ftps://localhost:2121', 
    auth=Basic('admin', 'secret'),
    ssl=ssl,
    limits=Limits(connections=50)
)

async with ftp.server() as server:
    print("Secure FTPS server running")
    # Server automatically handles SSL/TLS connections
```

### Web Interface API
The server provides HTTP endpoints for file management:
```python
# Server automatically creates these endpoints:
# GET  /                    - Server status and information
# GET  /files/{path}        - Download files
# POST /files/{path}        - Upload files (multipart/form-data)
# DELETE /files/{path}      - Delete files

# Example HTTP usage:
# curl -X GET http://localhost:2122/files/data.txt
# curl -X POST -F "file=@local.txt" http://localhost:2122/files/remote.txt  
# curl -X DELETE http://localhost:2122/files/old.txt
```

## Event Hooks
Register callbacks for monitoring and custom behavior:
```python
from ftppy import FtpPy

async def connect(connection):
    print(f"Connected to FTP server: {connection}")

async def error(error):
    print(f"FTP error occurred: {error}")

async def upload(source, target):
    print(f"Uploading {source} to {target}")

async def request(request, response, duration):
    print(f"{request.method} {request.path} - {response.status} ({duration:.2f}s)")

# Configure hooks
hooks = {
    'connect': connect,
    'error': error,
    'upload': upload,
    'download': upload,  # Same handler for downloads
    'request': request
}

ftp = FtpPy('ftp://server.com', hooks=hooks)
```

## Error Handling
FtpPy uses warning-based error handling instead of exceptions for most operations:
```python
from ftppy import FtpPy
import warnings

async def handle():
    ftp = FtpPy('ftp://server.com')
    
    try:
        async with ftp.client() as client:
            # Operations return boolean success status
            success = await client.upload('file.txt', '/remote.txt')
            if success:
                print("Upload completed successfully")
            else:
                print("Upload failed - check warnings for details")
                
            # File operations return None on failure
            metadata = await client.metadata('/nonexistent.txt')
            if metadata:
                print(f"File size: {metadata['size']}")
            else:
                print("File not found or inaccessible")
                
    except ConnectionError as error:
        print(f"Connection failed: {error}")
    except Exception as error:
        print(f"Unexpected error: {error}")

# Enable warning display for debugging
warnings.simplefilter('always')
```
**Note:** Failed operations return `False` or `None` and emit warnings rather than raising exceptions, allowing graceful degradation in batch operations.

## Connection Management
The library handles connection lifecycle automatically:
```python
from ftppy import FtpPy

# Connection pooling and management
ftp = FtpPy('ftp://server.com', limits=Limits(connections=10))

async with ftp.client() as client:
    # Main connection established here
    # Pool of additional connections created automatically
    
    # All operations share the connection pool
    await client.batch([('file1.txt', '/f1.txt'), ('file2.txt', '/f2.txt')])
    
    # Connections automatically released after operations
    stats = await client.stats()
    print(f"Active connections: {stats['active']}")
    
# All connections automatically closed and cleaned up here
```
**Connection Features:** Automatic connection pooling, graceful error handling, connection reuse, proper resource cleanup, SSL/TLS support, passive/active mode configuration, and automatic retry on connection failures.
