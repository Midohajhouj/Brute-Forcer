# Brute (prototype)

![Version](https://img.shields.io/badge/Version-1.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Author](https://img.shields.io/badge/Author-MIDØ-orange)

A powerful and customizable toolkit designed for ethical penetration testing and brute-force attacks on various services such as SSH, FTP, SMTP, and more. The tool is intended for authorized security testing and ethical hacking purposes only.

---

## 🔥 Features

- **Multi-Service Support**: Perform brute-force attacks on SSH, FTP, SMTP, and other common services.
- **Threading for High Performance**: Execute multiple attempts simultaneously with configurable threading.
- **Proxy Support**: Route attacks through SOCKS proxies for anonymity.
- **CAPTCHA Handling**: Integrates OCR via Tesseract for CAPTCHA-based challenges.
- **Customizable Wordlists**: Use your own wordlists for usernames and passwords.
- **Logging and Reporting**: Detailed logs with timestamps and rotating log files for efficiency.
- **Hash Cracking**: Support for cracking hashes using wordlists.
- **Cross-Platform Compatibility**: Works on Linux, macOS, and Windows.

---

## 📜 Requirements

Ensure the following libraries and dependencies are installed on your system:

### System Dependencies
- Python 3.6+
- Tesseract OCR (for CAPTCHA handling)
- Network access to the target system

### Python Libraries
The toolkit requires the following Python libraries:

```bash
paramiko
mysql-connector-python
pytesseract
Pillow
bcrypt
socks
tqdm
requests
```

Install all dependencies using pip:

```bash
pip install paramiko mysql-connector-python pytesseract Pillow bcrypt PySocks tqdm requests --break-system-packages
```

---

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Midohajhouj/Brute-Force-Toolkit.git
   cd Brute-Force-Toolkit
   ```

2. Ensure permissions are set:
   ```bash
   chmod +x brute.py
   ```

3. Run the toolkit:
   ```bash
   python3 brute.py
   ```

---

## 🛠 Usage

### Basic Usage
```bash
python3 brute.py --service ssh --host 192.168.1.100 --username root --wordlist passwords.txt
```

### Options
| Flag                  | Description                                    |
|-----------------------|------------------------------------------------|
| `--service`           | Specify the target service (e.g., ssh, ftp).  |
| `--host`              | Target host IP or domain.                     |
| `--username`          | Username to brute-force.                      |
| `--wordlist`          | Path to the password wordlist.                |
| `--proxy`             | Optional: SOCKS proxy for anonymity.          |
| `--threads`           | Number of threads (default: 10).              |
| `--log`               | Save results to a log file.                   |

### Example
```bash
python3 brute.py --service ftp --host ftp.example.com --username admin --wordlist passwords.txt --threads 20
```

---

## 🖼️ Sample Output

```plaintext
[+] Starting brute-force attack on SSH (192.168.1.100) with username 'root'
[+] Attempting password: password123
[!] Login failed for password: password123
[+] Attempting password: admin123
[✔] Login successful! Username: root | Password: admin123
```

---

## ⚠️ Disclaimer

This toolkit is designed for **authorized penetration testing and educational purposes only**. Use this tool responsibly and ensure you have proper permissions before initiating any tests.

**The author is not responsible for any misuse or unauthorized activities performed with this tool.**

---

## 📄 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## 🤝 Contribution

Contributions are welcome! Feel free to fork this repository, create new features, or report issues.

1. Fork the project.
2. Create your feature branch: `git checkout -b feature/AmazingFeature`.
3. Commit your changes: `git commit -m 'Add some AmazingFeature'`.
4. Push to the branch: `git push origin feature/AmazingFeature`.
5. Open a pull request.

---

#### **<p align="center"> Coded by [LIONMAD](https://github.com/Midohajhouj)</p>**
