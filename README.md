# LoopHunter
LoopHunter is a simple yet powerful web security scanning tool written in Python. It helps identify common vulnerabilities in web applications, including SQL Injection, Cross-Site Scripting (XSS), OS Command Injection, and more. This tool also checks for basic security misconfigurations such as missing security headers and a lack of CSRF protection.

## Features

- **SQL Injection Detection**: Detects potential SQL Injection vulnerabilities.
- **OS Command Injection Detection**: Identifies potential OS Command Injection points.
- **XSS (Cross-Site Scripting) Detection**: Finds possible XSS vulnerabilities.
- **Admin Panel Finder**: Searches for common admin panel paths.
- **CSRF Protection Check**: Checks if CSRF tokens are missing.
- **Security Headers Check**: Analyzes security headers to detect misconfigurations.

## Usage

1. Clone this repository to your local machine.
2. Ensure you have Python installed (version 3.x recommended).
3. Install the required libraries:
   ```bash
   pip install requests beautifulsoup4
   ```
4. Run the script:
   ```bash
   python loophunter.py
   ```
5. Enter the target URL when prompted (include `http://` or `https://`).

## Example
```
Enter the target URL (with http/https): http://example.com

[+] Scanning target: http://example.com
[+] Potential SQL Injection vulnerability detected at: http://example.com
[+] Potential OS Command Injection at: http://example.com
[+] XSS vulnerability detected at: http://example.com
[+] Missing X-Frame-Options header. Security misconfiguration detected.
[+] Admin panel found at: http://example.com/admin/

[+] Scan completed. Review the findings above.
```

## Important Notes

- This tool is intended for educational purposes and ethical hacking only. Do not use it on unauthorized websites.
- Always obtain proper authorization before conducting any security scans.

## Contact

For any questions, suggestions, or collaboration opportunities, feel free to reach out:

- **Instagram**: [magicianslime](https://instagram.com/magicianslime)
- **Telegram**: [magician_slime](https://t.me/magician_slime)
- **GitHub**: [magicianKaif](https://github.com/magicianKaif)

---

Happy Hacking with LoopHunter!

