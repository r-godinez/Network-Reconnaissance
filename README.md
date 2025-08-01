# 🛡️ Network Security Scanner

A comprehensive **Network Security Scanner** built in Go, designed to demonstrate essential techniques you'll need as a **Cybersecurity Forensics Analyst**. This tool mimics key behaviors of tools like `nmap`, with custom implementations for scanning and enumeration.

---

## 🚀 Key Features

### 🔍 1. Host Discovery

- Performs **ping sweeps** and **port probes** to identify live hosts.
- Foundational for network reconnaissance.

### 🚪 2. Port Scanning

- **Multi-threaded TCP port scanning** for fast enumeration.
- Targets common vulnerable ports: `21`, `22`, `23`, `25`, `53`, `80`, `443`, etc.
- Similar in behavior to `nmap -sT`, but fully written in **Go**.

### 🧠 3. Service Detection

- Identifies running services on open ports.
- Performs **version detection** for services like Apache, nginx, OpenSSH, etc.

### 🪪 4. Banner Grabbing

- Collects service banners for **fingerprinting**.
- Useful in identifying vulnerabilities and misconfigurations.

### 🌐 5. HTTP Enumeration

- Inspects web servers and web apps.
- Extracts:
  - Page titles
  - HTTP headers
  - Server info
- Helps uncover potential attack surfaces.

### 🔐 6. TLS/SSL Analysis

- Evaluates certificate validity and HTTPS configuration.
- Flags:
  - Weak ciphers
  - Outdated protocol versions
  - Security misconfigurations

---

## ⚙️ Setup

### 1. Initialize the Go Module

```bash
go mod init network-scanner
go build -o scanner network-scanner.go
# or if your entry file is named scanner.go
go build -o scanner scanner.go
```

### 2. Compile the Scanner

```bash
go build -o scanner network-scanner.go
# or if your entry file is named scanner.go
go build -o scanner scanner.go
```

## 🧪 How to Use

- ⚠️ Use this tool only on networks you own or are authorized to scan.

### Scan a Target

```bash
./scanner scanme.nmap.org
./scanner 192.168.1.1
```

### Scan Localhost

```bash
go run scanner.go localhost
```

### Find Your Router IP (macOS/Linux)

```bash
netstat -rn | grep default
```

### Try Scanning Your Router (if you own it)

```bash
go run scanner.go 192.168.1.1
```
