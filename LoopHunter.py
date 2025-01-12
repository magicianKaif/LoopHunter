import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json

# Basic setup
target_url = input("Enter the target URL (with http/https): ")
session = requests.Session()

# Function to check for SQL Injection
def check_sql_injection(url, payload="' OR '1'='1"):
    test_url = url + f"?test={payload}"
    response = session.get(test_url)
    if "syntax" in response.text.lower() or "mysql" in response.text.lower():
        print("[+] Potential SQL Injection vulnerability detected at:", url)

# Function to test for OS Command Injection
def check_command_injection(url, command="; ls"):
    response = session.get(url + command)
    if "root" in response.text or "bin" in response.text:
        print("[+] Potential OS Command Injection at:", url)

# Function to check for XSS
def check_xss(url, payload="<script>alert('xss')</script>"):
    params = {'test': payload}
    response = session.get(url, params=params)
    if payload in response.text:
        print("[+] XSS vulnerability detected at:", url)

# Function to find admin panel
def find_admin_panel():
    paths = ["admin/", "admin/login", "admin.php"]
    for path in paths:
        test_url = urljoin(target_url, path)
        response = session.get(test_url)
        if response.status_code == 200:
            print("[+] Admin panel found at:", test_url)
            break

# Function to check for CSRF tokens
def check_csrf_protection(url):
    response = session.get(url)
    if not re.search(r'name=["\']csrf_token["\']', response.text):
        print("[+] CSRF token not found. Potential CSRF vulnerability at:", url)

# Function to check for security headers
def check_security_headers(url):
    response = session.head(url)
    headers_to_check = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
    for header in headers_to_check:
        if header not in response.headers:
            print(f"[+] Missing {header} header. Security misconfiguration detected.")

# Start scanning
print("\n[+] Scanning target:", target_url)

# Perform basic scans
check_sql_injection(target_url)
check_command_injection(target_url)
check_xss(target_url)
check_csrf_protection(target_url)
check_security_headers(target_url)
find_admin_panel()

print("\n[+] Scan completed. Review the findings above.")
