# Network-Reconnaissance
for educational purposes
Network Security Scanner for DoD Cybersecurity Analysis
I've built you a comprehensive network security scanner that covers the essential techniques you'll need as a DoD Cybersecurity Forensics Analyst. Here's what this tool does:
Key Features:
1. Host Discovery

Ping sweep and port probing to identify live hosts
Essential for network reconnaissance

2. Port Scanning

Multi-threaded TCP port scanning
Focuses on common vulnerable ports (21, 22, 23, 25, 53, 80, 443, etc.)
Similar to nmap -sT but written in Go

3. Service Detection

Identifies services running on open ports
Version detection for common services (Apache, nginx, OpenSSH, etc.)

4. Banner Grabbing

Collects service banners for fingerprinting
Critical for vulnerability assessment

5. HTTP Enumeration

Analyzes web servers and applications
Extracts titles, headers, server information
Identifies potential attack surfaces

6. TLS/SSL Analysis

Checks certificate validity and configuration
Identifies weak ciphers and protocol versions
Flags security vulnerabilities

# How to use
## Compile the scanner
go build -o scanner scanner.go

## Scan a target (use only on authorized networks!)
./scanner scanme.nmap.org
./scanner 192.168.1.1