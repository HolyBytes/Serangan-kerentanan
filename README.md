# 🚀 BugPent CyberCore v2.0 BETA

<div align="center">

```
  ____            _       ____        _   _                  
 | __ ) _   _  __| |_   _|  _ \ _   _| |_| |__   ___  _ __  
 |  _ \| | | |/ _` | | | | |_) | | | | __| '_ \ / _ \| '_ \ 
 | |_) | |_| | (_| | |_| |  __/| |_| | |_| | | | (_) | | | |
 |____/ \__,_|\__,_|\__, |_|    \__, |\__|_| |_|\___/|_| |_|
                    |___/       |___/                        
```

🔥 **Advanced Web Vulnerability Scanner & Admin Panel Hunter** 🔥

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0%20BETA-red.svg)](https://github.com/HolyBytes/Serangan-kerentanan)

**Developed by** [HolyBytes](https://github.com/HolyBytes) | **Team** BugPent CyberCore

</div>

---

## 🎯 Apa itu BugPent CyberCore?

Tool penetration testing canggih yang menggabungkan **Admin Panel Discovery** dan **Vulnerability Scanner** dalam satu package. Dirancang khusus untuk security researcher dan ethical hacker yang membutuhkan tool comprehensive untuk web application testing.

## ✨ Fitur Unggulan

### 🔍 **Admin Panel Hunter**
- 🎯 **200+ Path Discovery** - Database path admin panel terlengkap
- ⚡ **Multi-Threading** - Scanning super cepat dengan dukungan thread
- 📊 **Real-time Progress** - Animasi loading dengan counter live
- 🎚️ **Level Control** - Intensitas scan dari ringan sampai brutal (1-20)

### 🛡️ **Vulnerability Scanner**
- 💉 **SQL Injection** - 20+ payload variations
- 🚨 **Cross-Site Scripting (XSS)** - 14+ bypass techniques  
- 📁 **File Inclusion (LFI/RFI)** - Local & remote file access
- 💻 **Remote Code Execution** - Command injection detection
- 🔐 **Authentication Bypass** - JWT tampering & NoSQL injection
- 🌐 **Server-Side Attacks** - SSRF, XXE, SSTI detection

### 🎨 **User Experience**
- 🌈 **Colorful Interface** - Eye-catching terminal output
- 📋 **Structured Results** - Clean table format hasil scan
- 🔒 **Anti-Tamper** - Protection terhadap file modification
- 📱 **Cross-Platform** - Windows, Linux, macOS compatible

---

## 🚀 Quick Start

### 📋 Prerequisites

```bash
# Install required packages
pip install requests colorama beautifulsoup4
```

### 📥 Installation

```bash
# Clone repository
git clone https://github.com/HolyBytes/Serangan-kerentanan.git

# Navigate to directory  
cd Serangan-kerentanan

# Set executable permission (Linux/macOS)
chmod +x bugpent.py
```

### 🏃‍♂️ Running the Tool

```bash
# Execute the scanner
python3 bugpent.py
```

---

## 🎮 Cara Penggunaan

### 📝 **Input Parameters**

1. **🎯 Target URL**
   ```
   [?] Masukkan target URL: example.com
   ```
   
2. **⚡ Scan Level (1-20)**
   ```
   [?] Masukkan level scan (1-20): 15
   ```

### 📊 **Level Scanning Guide**

| Level | Paths | Description | Use Case |
|-------|--------|-------------|----------|
| 🟢 **1-5** | 10-50 | Basic scan | Quick reconnaissance |
| 🟡 **6-10** | 60-100 | Medium scan | Standard testing |
| 🟠 **11-15** | 110-150 | Advanced scan | Thorough assessment |
| 🔴 **16-20** | 160-200+ | Comprehensive | Full security audit |

---

## 🛡️ Kerentanan yang Dapat Dideteksi

<table>
<tr>
<td width="50%">

### 💀 **Injection Attacks**
- 💉 **SQL Injection** - Database manipulation
- 🧬 **NoSQL Injection** - MongoDB/Redis attacks  
- 💊 **LDAP Injection** - Directory service bypass
- 🏗️ **Command Injection** - OS command execution

### 🌐 **Web Application Attacks**
- 🚨 **Cross-Site Scripting (XSS)** - Client-side code injection
- 🔗 **Cross-Site Request Forgery** - Unauthorized actions
- 🎭 **Server-Side Template Injection** - Template engine abuse
- 📄 **XML External Entity (XXE)** - XML parser exploitation

</td>
<td width="50%">

### 📁 **File & Directory Attacks**
- 📂 **Local File Inclusion (LFI)** - Server file access
- 🌍 **Remote File Inclusion (RFI)** - Remote code execution
- 🗂️ **Directory Traversal** - Path manipulation
- 📤 **File Upload Bypass** - Malicious file upload

### 🔐 **Authentication & Authorization**
- 🎫 **JWT Tampering** - Token manipulation
- 🚪 **Authentication Bypass** - Login circumvention
- 🔑 **Session Fixation** - Session hijacking
- 🌊 **Open Redirect** - URL redirection abuse

</td>
</tr>
</table>

---

## 📊 Sample Output

### 🎯 **Admin Panel Discovery**
```
╔══════════════════════════════════════════════════╗
║ HASIL SCAN ADMIN PANEL                          ║
╚══════════════════════════════════════════════════╝
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
| URL                                        | Title         |
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
| http://target.com/admin                    | Admin Login   |
| http://target.com/wp-admin                 | WordPress     |
| http://target.com/phpmyadmin              | phpMyAdmin    |
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
```

### 🚨 **Vulnerability Detection**
```
╔══════════════════════════════════════════════════╗
║ KERENTANAN YANG DITEMUKAN                       ║
╚══════════════════════════════════════════════════╝
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
| Tipe Kerentanan              | Payload                   |
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
| SQL Injection               | 1' OR '1'='1              |
| XSS                        | <script>alert('XSS')      |
| LFI                        | ../../../../etc/passwd     |
+━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━+
```

---

## ⚙️ Advanced Configuration

### 🔧 **Threading Options**
```python
# Modify in source code
threads = 20  # Increase for faster scanning
```

### 🎚️ **Custom Payloads**
```python
# Add custom payloads to PAYLOADS dictionary
CUSTOM_PAYLOADS = {
    "Custom Attack": [
        "your_payload_here",
        "another_payload"
    ]
}
```

---

## ⚠️ Legal Disclaimer

<div align="center">

### 🚨 **IMPORTANT NOTICE** 🚨

</div>

> **⚖️ Legal Use Only**: Tool ini dikembangkan untuk tujuan **educational** dan **authorized penetration testing**. 
> 
> **🎯 Authorized Testing**: Pastikan Anda memiliki izin tertulis sebelum melakukan testing pada sistem target.
> 
> **❌ Prohibited Actions**: Penggunaan untuk aktivitas ilegal, unauthorized access, atau merugikan pihak lain **DILARANG KERAS**.
> 
> **🛡️ Responsibility**: Developer dan tim tidak bertanggung jawab atas penyalahgunaan tool ini.

---

## 👨‍💻 Developer Information

<div align="center">

### 🌟 **HolyBytes Development Team** 🌟

</div>

<table align="center">
<tr>
<td align="center">

**🧑‍💻 Lead Developer**<br>
**Ade Pratama (HolyBytes)**

[![GitHub](https://img.shields.io/badge/GitHub-HolyBytes-black.svg?logo=github)](https://github.com/HolyBytes)
[![Saweria](https://img.shields.io/badge/Support-Saweria-orange.svg)](https://saweria.co/HolyBytes)

</td>
<td align="center">

**🏢 Organization**<br>
**BugPent CyberCore**

[![Team](https://img.shields.io/badge/Team-BugPent%20CyberCore-blue.svg)](https://github.com/HolyBytes)
[![Version](https://img.shields.io/badge/Version-2.0%20BETA-red.svg)](https://github.com/HolyBytes/Serangan-kerentanan)

</td>
</tr>
</table>

---

## 🤝 Contributing

### 🎯 **How to Contribute**

1. 🍴 **Fork** the repository
2. 🌿 **Create** feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 **Commit** changes (`git commit -m 'Add AmazingFeature'`)
4. 📤 **Push** to branch (`git push origin feature/AmazingFeature`)
5. 🔄 **Open** Pull Request

### 💡 **Ideas Welcome**

- 🚀 New vulnerability detection methods
- 🎨 UI/UX improvements  
- 📊 Reporting features
- 🔧 Performance optimizations

---

## 📞 Support & Contact

<div align="center">

### 🆘 **Need Help?**

[![Issues](https://img.shields.io/badge/Issues-GitHub-red.svg?logo=github)](https://github.com/HolyBytes/Serangan-kerentanan/issues)
[![Discussions](https://img.shields.io/badge/Discussions-GitHub-blue.svg?logo=github)](https://github.com/HolyBytes/Serangan-kerentanan/discussions)

**💰 Support Development**: [Saweria.co/HolyBytes](https://saweria.co/HolyBytes)

</div>

---

<div align="center">

### 🌟 **Star this repository if you find it useful!** 🌟

**Made with ❤️ by BugPent CyberCore Team**

</div>
