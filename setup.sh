#!/bin/bash

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

# Colors for stylish output
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
RED="\033[1;31m"
RESET="\033[0m"  # Reset color

# Logging configuration
PIP_LOG="pip_install.log"

display_banner() {
    # Display a stylish banner
    echo -e "${BLUE}"
    echo "██████████████████████████████████████████████████"
    echo "██                                              ██"
    echo "██          Brute Force Toolkit Setup           ██"
    echo "██       Advanced Penetration Testing           ██"
    echo "██                                              ██"
    echo "██  Supports: SSH, FTP, HTTP, Databases,        ██"
    echo "██  Web Apps, and more with brute force         ██"
    echo "██                                              ██"
    echo "██████████████████████████████████████████████████"
    echo -e "${RESET}"
}

install_system_dependencies() {
    echo -e "${GREEN}[INFO]${RESET} Updating package list..."
    if ! apt-get update -y; then
        echo -e "${RED}[ERROR]${RESET} Failed to update package list"
        exit 1
    fi

    echo -e "${GREEN}[INFO]${RESET} Installing required system packages..."
    if ! apt-get install -y \
        python3 python3-pip python3-venv \
        libssl-dev libffi-dev \
        tesseract-ocr libtesseract-dev \
        nmap tor proxychains; then
        echo -e "${RED}[ERROR]${RESET} Failed to install system packages"
        exit 1
    fi
}

install_python_packages() {
    echo -e "${GREEN}[INFO]${RESET} Installing required Python packages (output logged to ${PIP_LOG})..."
    local packages=(
        argparse
        requests
        paramiko
        mysql-connector-python
        pytesseract
        bcrypt
        socks
        tqdm
        selenium
        beautifulsoup4
        dnspython
        python-nmap
        ldap3
        cryptography
        mechanize
        fake-useragent
        pyodbc
        psycopg2-binary
        pymongo
        redis
        pyfiglet
        colorama
        scapy
        sqlalchemy
        python-whois
        pyOpenSSL
        pillow
    )

    for package in "${packages[@]}"; do
        if ! pip install --break-system-packages "$package" >> "$PIP_LOG" 2>&1; then
            echo -e "${RED}[ERROR]${RESET} Failed to install ${package}. Check ${PIP_LOG} for details."
            exit 1
        fi
        echo "$(date) - INFO - Successfully installed $package" >> "$PIP_LOG"
    done
}

create_symlink() {
    echo -e "${YELLOW}[*]${RESET} Creating symlink for easy access..."

    # Check if the source file exists
    if [ ! -f "brute.py" ]; then
        echo -e "${RED}[ERROR]${RESET} brute.py not found in the current directory."
        exit 1
    fi

    # Remove existing symlink if present
    if [ -e "/usr/local/bin/brute" ]; then
        echo -e "${YELLOW}[INFO]${RESET} Removing existing symlink..."
        if ! sudo rm "/usr/local/bin/brute"; then
            echo -e "${RED}[ERROR]${RESET} Failed to remove existing symlink"
            exit 1
        fi
    fi

    # Create a new symlink
    if ! sudo cp "brute.py" "/usr/local/bin/brute"; then
        echo -e "${RED}[ERROR]${RESET} Failed to copy brute.py to /usr/local/bin"
        exit 1
    fi

    if ! sudo chmod +x "/usr/local/bin/brute"; then
        echo -e "${RED}[ERROR]${RESET} Failed to make brute executable"
        exit 1
    fi

    # Verify symlink creation
    if [ -e "/usr/local/bin/brute" ]; then
        echo -e "${GREEN}[SUCCESS]${RESET} Symlink created! You can now run 'brute' from anywhere."
    else
        echo -e "${RED}[ERROR]${RESET} Symlink creation failed."
        exit 1
    fi
}

create_directories() {
    echo -e "${GREEN}[INFO]${RESET} Creating required directories..."
    local directories=('wordlists' 'results' 'temp')
    
    for directory in "${directories[@]}"; do
        if ! mkdir -p "$directory"; then
            echo -e "${RED}[ERROR]${RESET} Failed to create directory ${directory}"
            exit 1
        fi
        echo -e "${GREEN}[+] Created directory: ${directory}${RESET}"
    done
}

download_default_wordlists() {
    echo -e "${GREEN}[INFO]${RESET} Checking for default wordlists..."
    declare -A wordlists=(
        ['common_usernames.txt']='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt'
        ['common_passwords.txt']='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt'
        ['common_subdomains.txt']='https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt'
    )

    for filename in "${!wordlists[@]}"; do
        filepath="wordlists/$filename"
        if [ ! -e "$filepath" ]; then
            echo -e "${YELLOW}[*]${RESET} Downloading $filename..."
            if ! wget -O "$filepath" "${wordlists[$filename]}"; then
                echo -e "${RED}[ERROR]${RESET} Failed to download $filename"
                # Not critical, so continue
                continue
            fi
            echo -e "${GREEN}[+] Successfully downloaded $filename${RESET}"
        fi
    done
}

main() {
    display_banner

    # Ensure the script is being run as root or with sudo
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[ERROR]${RESET} This script must be run as root or with sudo."
        exit 1
    fi

    # Install system dependencies
    install_system_dependencies

    # Install Python packages
    install_python_packages

    # Create required directories
    create_directories

    # Download default wordlists
    download_default_wordlists

    # Create a symlink for easy access
    create_symlink

    # Completion message
    echo -e "${GREEN}[INFO]${RESET} Setup complete! Brute Force Toolkit is now ready to use."
    echo -e "${BLUE}You can now run the tool using:${RESET}"
    echo -e "${GREEN}brute --help${RESET}"

    echo -e "${BLUE}"
    echo "████████████████████████████████████████████████████"
    echo "██                                                ██"
    echo "██           Installation Complete               ██"
    echo "██      Brute Force Toolkit Ready               ██"
    echo "██                                                ██"
    echo "████████████████████████████████████████████████████"
    echo -e "${RESET}"
}

main "$@"
