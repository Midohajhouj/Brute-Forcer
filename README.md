# Brute Force Toolkit v1.0 (Unstable)

![Version](https://img.shields.io/badge/Version-1.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Author](https://img.shields.io/badge/Author-MIDØ-orange)

Advanced penetration testing toolkit with brute-force capabilities for multiple services.

## Features

- Multi-service brute force attacks (SSH, FTP, HTTP, WordPress, etc.)
- Password strength analysis and wordlist generation
- Session management and result tracking
- DNS/subdomain enumeration
- Web scraping and CAPTCHA solving
- Network scanning capabilities
- Interactive shell interface

## Installation

1. **Prerequisites**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
   ```

2. **Install the toolkit**:
   ```bash
   git clone https://github.com/yourusername/brute-force-toolkit.git
   cd brute-force-toolkit
   sudo python3 setup.py install
   ```

3. **Install dependencies**:
   ```bash
   pip3 install -r requirements.txt --break-system-packages
   ```

## Configuration

The toolkit automatically creates its directory structure at `/opt/brute/`:

```
/opt/brute/
├── config.ini       # Configuration file
├── session.dat      # Session data
├── wordlists/       # Default wordlists
├── results/         # Output files
├── brute.log        # Log file
└── temp/            # Temporary files
```

## Usage

### Basic Command Syntax

To use the toolkit, run the following syntax in your terminal:

```bash
brute -t <target> -s <service> -U <userlist> -P <passwordlist> [options]
```

- `-t <target>`: The target system or website you want to attack.
- `-s <service>`: The service to attack (such as `ssh`, `ftp`, `http`, `wordpress`, etc.).
- `-U <userlist>`: A file containing a list of usernames to test.
- `-P <passwordlist>`: A file containing a list of passwords to test.

### Additional Options:

| Option        | Description                                    | Example Usage                                         |
|---------------|------------------------------------------------|-------------------------------------------------------|
| `-v`          | Show the current version of the toolkit.      | `brute -v`                                            |
| `-V`          | Enable verbose output.                        | `brute -V`                                            |
| `-t`          | Set the target host or URL for brute-force.    | `brute -t 192.168.1.100`                              |
| `-s`          | Specify the service (ssh, ftp, http, wordpress). | `brute -s ssh`                                        |
| `-U`          | Define the path to the username list file.     | `brute -U users.txt`                                  |
| `-P`          | Define the path to the password list file.     | `brute -P passwords.txt`                              |
| `-T`          | Specify a list of targets (IPs/URLs) to attack. | `brute -T targets.txt`                                |
| `--threads`   | Number of threads to use for parallel attacks.  | `brute --threads 10`                                  |
| `--proxy`     | Use proxies for anonymous attacks.             | `brute --proxy proxylist.txt`                         |
| `--timeout`   | Set a timeout for each request (in seconds).    | `brute --timeout 30`                                  |
| `-i`          | Launch interactive mode to configure the toolkit. | `brute -i`                                            |

### Common Usage Examples

#### 1. **SSH Brute-Force Attack**
```bash
brute -t 192.168.1.100 -s ssh -U users.txt -P passwords.txt
```

#### 2. **WordPress Brute-Force Attack**
```bash
brute -t http://example.com/wp-login.php -s wordpress -U admins.txt -P rockyou.txt
```

#### 3. **FTP Brute-Force Attack**
```bash
brute -t ftp://example.com -s ftp -U users.txt -P passwords.txt
```

#### 4. **Subdomain Enumeration**
```bash
brute --subdomain example.com --subdomain-list subdomains.txt
```

#### 5. **DNS Enumeration**
```bash
brute -t example.com -s dns --subdomain-list subdomains.txt
```

## 🖥 Interactive Shell Mode

The **Interactive Shell Mode** allows you to manage attacks and settings without typing commands manually each time.

### Launch Interactive Mode

```bash
brute -i
```

### Available Commands in Interactive Mode:

1. **`help`**: Displays all available commands in interactive mode.
   
2. **`set`**: Configure attack parameters such as target, service, username, password lists, etc.
   
3. **`run`**: Start the configured attack with the current parameters.
   
4. **`scan`**: Perform a network scan to identify open services on the target.
   
5. **`report`**: Generate a report of the attack results in various formats (CSV, PDF, etc.).
   
6. **`exit`**: Exit interactive mode.

## 🛠 Advanced Usage

### 1. **Using Proxies for Anonymity**
```bash
brute -t 192.168.1.100 -s ssh -U users.txt -P passwords.txt --proxy proxylist.txt
```

### 2. **Running with Multiple Targets**
```bash
brute -T targets.txt -s ssh -U users.txt -P passwords.txt --threads 10
```

### 3. **Increasing Speed with Threads**
```bash
brute -t 192.168.1.100 -s ssh -U users.txt -P passwords.txt --threads 50
```

## 📝 Reporting

After conducting brute-force attacks, you can generate detailed reports of the attack results.

- **CSV**: `brute report --format csv --output results.csv`
- **PDF**: `brute report --format pdf --output results.pdf`
- **HTML**: `brute report --format html --output results.html`

## ⚖️ Legal Disclaimer

**Brute Force Toolkit** is intended solely for **ethical penetration testing** and **security research**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The developers assume **no responsibility** for any misuse or damage caused by this tool.

## 📝 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.

## 🤝 Support

If you encounter any issues or have feature requests, please open an issue on [GitHub Issues](https://github.com/yourusername/brute-force-toolkit/issues).

#### *<p align="center"> Coded by <a href="https://github.com/yourusername">YourUsername</a> </p>*
