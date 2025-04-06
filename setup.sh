#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          brute_installer
# Required-Start:    $network $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Advanced Brute Force Toolkit
# Description:       A powerful penetration testing tool with brute force capabilities for multiple services.
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO ###

import os
import sys
import subprocess
import logging
from setuptools import setup, find_packages
from setuptools.command.install import install

# Colors for stylish output
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
BLUE = "\033[1;34m"
RED = "\033[1;31m"
RESET = "\033[0m"  # Reset color

# Logging configuration
PIP_LOG = "pip_install.log"
logging.basicConfig(filename=PIP_LOG, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def display_banner():
    """Display a stylish banner."""
    print(f"{BLUE}")
    print("██████████████████████████████████████████████████")
    print("██                                              ██")
    print("██          Brute Force Toolkit Setup           ██")
    print("██       Advanced Penetration Testing           ██")
    print("██                                              ██")
    print("██  Supports: SSH, FTP, HTTP, Databases,        ██")
    print("██  Web Apps, and more with brute force         ██")
    print("██                                              ██")
    print("██████████████████████████████████████████████████")
    print(f"{RESET}")

def install_system_dependencies():
    """Install system dependencies using apt-get."""
    print(f"{GREEN}[INFO]{RESET} Updating package list...")
    try:
        subprocess.run(["apt-get", "update", "-y"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to update package list: {e}")
        sys.exit(1)

    print(f"{GREEN}[INFO]{RESET} Installing required system packages...")
    try:
        subprocess.run(
            ["apt-get", "install", "-y", 
             "python3", "python3-pip", "python3-venv",
             "libssl-dev", "libffi-dev",
             "tesseract-ocr", "libtesseract-dev",
             "nmap", "tor", "proxychains"],
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to install system packages: {e}")
        sys.exit(1)

def install_python_packages():
    """Install required Python packages and log the output."""
    print(f"{GREEN}[INFO]{RESET} Installing required Python packages (output logged to {PIP_LOG})...")
    packages = [
        "argparse",
        "requests",
        "paramiko",
        "mysql-connector-python",
        "pytesseract",
        "bcrypt",
        "socks",
        "tqdm",
        "selenium",
        "beautifulsoup4",
        "vobject",
        "dnspython",
        "python-nmap",
        "ldap3",
        "cryptography",
        "mechanize",
        "fake-useragent",
        "pyodbc",
        "psycopg2-binary",
        "pymongo",
        "redis",
        "pyfiglet",
        "colorama",
        "scapy",
        "sqlalchemy",
        "python-whois",
        "pyOpenSSL",
        "pillow"
    ]

    for package in packages:
        try:
            subprocess.run(
                ["pip", "install", "--break-system-packages", package],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            logging.info(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to install {package}: {e.stderr.decode()}")
            print(f"{RED}[ERROR]{RESET} Failed to install {package}. Check {PIP_LOG} for details.")
            sys.exit(1)

def create_symlink():
    """Create a symlink for easy access to the brute force toolkit."""
    print(f"{YELLOW}[*]{RESET} Creating symlink for easy access...")

    # Check if the source file exists
    if not os.path.isfile("brute.py"):
        print(f"{RED}[ERROR]{RESET} brute.py not found in the current directory.")
        sys.exit(1)

    # Remove existing symlink if present
    if os.path.exists("/usr/local/bin/brute"):
        print(f"{YELLOW}[INFO]{RESET} Removing existing symlink...")
        try:
            subprocess.run(["sudo", "rm", "/usr/local/bin/brute"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[ERROR]{RESET} Failed to remove existing symlink: {e}")
            sys.exit(1)

    # Create a new symlink
    try:
        subprocess.run(["sudo", "cp", "brute.py", "/usr/local/bin/brute"], check=True)
        subprocess.run(["sudo", "chmod", "+x", "/usr/local/bin/brute"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}[ERROR]{RESET} Failed to create symlink: {e}")
        sys.exit(1)

    # Verify symlink creation
    if os.path.exists("/usr/local/bin/brute"):
        print(f"{GREEN}[SUCCESS]{RESET} Symlink created! You can now run 'brute' from anywhere.")
    else:
        print(f"{RED}[ERROR]{RESET} Symlink creation failed.")
        sys.exit(1)

def create_directories():
    """Create required directories for the toolkit."""
    print(f"{GREEN}[INFO]{RESET} Creating required directories...")
    directories = ['wordlists', 'results', 'temp']
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"{GREEN}[+] Created directory: {directory}{RESET}")
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to create directory {directory}: {e}")
            sys.exit(1)

def download_default_wordlists():
    """Download default wordlists if they don't exist."""
    print(f"{GREEN}[INFO]{RESET} Checking for default wordlists...")
    wordlists = {
        'common_usernames.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
        'common_passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt',
        'common_subdomains.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt'
    }

    for filename, url in wordlists.items():
        filepath = os.path.join('wordlists', filename)
        if not os.path.exists(filepath):
            try:
                print(f"{YELLOW}[*]{RESET} Downloading {filename}...")
                subprocess.run(["wget", "-O", filepath, url], check=True)
                print(f"{GREEN}[+] Successfully downloaded {filename}{RESET}")
            except subprocess.CalledProcessError as e:
                print(f"{RED}[ERROR]{RESET} Failed to download {filename}: {e}")
                # Not critical, so continue
                continue

class CustomInstall(install):
    """Custom installation class to handle system dependencies and setup."""

    def run(self):
        """Run the custom installation process."""
        display_banner()

        # Ensure the script is being run as root or with sudo
        if os.geteuid() != 0:
            print(f"{RED}[ERROR]{RESET} This script must be run as root or with sudo.")
            sys.exit(1)

        # Install system dependencies
        install_system_dependencies()

        # Install Python packages
        install_python_packages()

        # Create required directories
        create_directories()

        # Download default wordlists
        download_default_wordlists()

        # Create a symlink for easy access
        create_symlink()

        # Completion message
        print(f"{GREEN}[INFO]{RESET} Setup complete! Brute Force Toolkit is now ready to use.")
        print(f"{BLUE}You can now run the tool using:{RESET}")
        print(f"{GREEN}brute --help{RESET}")

        print(f"{BLUE}")
        print("████████████████████████████████████████████████████")
        print("██                                                ██")
        print("██           Installation Complete               ██")
        print("██      Brute Force Toolkit Ready               ██")
        print("██                                                ██")
        print("████████████████████████████████████████████████████")
        print(f"{RESET}")

# Define the setup configuration
setup(
    name="brute-toolkit",
    version="4.1",
    author="LIONMAD",
    description="Advanced brute force toolkit for penetration testing",
    long_description=open("README.md").read() if os.path.exists("README.md") else "Advanced brute force toolkit",
    long_description_content_type="text/markdown",
    url="https://github.com/Midohajhouj/brute",
    packages=find_packages(),
    install_requires=[
        "argparse",
        "requests>=2.25.1",
        "paramiko>=2.7.2",
        "mysql-connector-python>=8.0.23",
        "pytesseract>=0.3.8",
        "bcrypt>=3.2.0",
        "socks>=1.0.0",
        "tqdm>=4.59.0",
        "selenium>=3.141.0",
        "beautifulsoup4>=4.9.3",
        "dnspython>=2.1.0",
        "python-nmap>=0.7.1",
        "ldap3>=2.9.1",
        "cryptography>=3.4.7",
        "mechanize>=0.4.5",
        "fake-useragent>=0.1.11",
        "pyodbc>=4.0.30",
        "psycopg2-binary>=2.8.6",
        "pymongo>=3.11.3",
        "redis>=3.5.3",
        "pyfiglet>=0.8.post1",
        "colorama>=0.4.4",
        "scapy>=2.4.5",
        "sqlalchemy>=1.4.7",
        "python-whois>=0.8.0",
        "pyOpenSSL>=20.0.1",
        "pillow>=8.1.2"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'brute=brute:main',
        ],
    },
    cmdclass={
        'install': CustomInstall,
    },
)
