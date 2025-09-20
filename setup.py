from setuptools import setup, find_packages
import sys

# Check Python version requirement
if sys.version_info < (3, 9):
    raise RuntimeError("FtpPy requires Python 3.9 or newer")

setup(
    name="FtpPy",
    version="1.0.0",
    author="Andrew Hernandez",
    author_email="andromedeyz@hotmail.com",
    description="An efficient FTP client and server library in Python with robust connection management for reliable and streamlined file transfer operations.",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    url="http://github.com/ApaxPhoenix/FtpPy",
    project_urls={
        "Bug Tracker": "http://github.com/ApaxPhoenix/FtpPy/issues",
        "Source Code": "http://github.com/ApaxPhoenix/FtpPy",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: File Transfer Protocol (FTP)",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.9",
    install_requires=open("requirements.txt").readlines(),
    keywords="ftp, async, file transfer, networking, ssl, tls, server, client",
    license="MIT",
    zip_safe=False,  # Set to False for packages with data files or C extensions
    include_package_data=True,  # Include files specified in MANIFEST.in
)
