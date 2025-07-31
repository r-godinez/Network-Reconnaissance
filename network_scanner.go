package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult holds the results of various scans
type ScanResult struct {
	Target      string
	OpenPorts   []PortInfo
	Services    []ServiceInfo
	Banners     []BannerInfo
	HTTPInfo    []HTTPInfo
	TLSInfo     []TLSInfo
	Fingerprint OSFingerprint
}

type PortInfo struct {
	Port     int
	Protocol string
	State    string
	Service  string
}

type ServiceInfo struct {
	Port        int
	Service     string
	Version     string
	Fingerprint string
}

type BannerInfo struct {
	Port   int
	Banner string
}

type HTTPInfo struct {
	Port    int
	Status  int
	Server  string
	Headers map[string]string
	Title   string
}

type TLSInfo struct {
	Port            int
	Version         string
	Cipher          string
	Certificate     string
	Vulnerabilities []string
}

type OSFingerprint struct {
	OS           string
	Confidence   int
	TTL          int
	WindowSize   int
	Fingerprints []string
}

// NetworkScanner is the main scanner struct
type NetworkScanner struct {
	timeout    time.Duration
	maxWorkers int
	results    *ScanResult
	mu         sync.Mutex
}

func NewNetworkScanner(target string, timeout time.Duration, workers int) *NetworkScanner {
	return &NetworkScanner{
		timeout:    timeout,
		maxWorkers: workers,
		results: &ScanResult{
			Target:    target,
			OpenPorts: make([]PortInfo, 0),
			Services:  make([]ServiceInfo, 0),
			Banners:   make([]BannerInfo, 0),
			HTTPInfo:  make([]HTTPInfo, 0),
			TLSInfo:   make([]TLSInfo, 0),
		},
	}
}

// Common ports used in penetration testing
var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
}

// Service fingerprints for common services
var serviceFingerprints = map[string][]string{
	"SSH":        {"SSH-", "OpenSSH"},
	"HTTP":       {"HTTP/", "Server:"},
	"FTP":        {"220 ", "vsFTPd", "ProFTPD"},
	"SMTP":       {"220 ", "ESMTP"},
	"MySQL":      {"mysql_native_password", "MariaDB"},
	"PostgreSQL": {"FATAL", "invalid authentication"},
}

func main() {
	fmt.Println("🔍 DoD Network Security Scanner")
	fmt.Println("================================")
	fmt.Println("⚠️  WARNING: Only use on authorized networks!")
	fmt.Println("For educational and authorized testing purposes only.\n")

	if len(os.Args) < 2 {
		fmt.Println("Usage: ./scanner <target_ip_or_domain>")
		fmt.Println("Example: ./scanner 192.168.1.1")
		fmt.Println("Example: ./scanner scanme.nmap.org")
		os.Exit(1)
	}

	target := os.Args[1]
	scanner := NewNetworkScanner(target, 3*time.Second, 100)

	fmt.Printf("🎯 Target: %s\n", target)
	fmt.Printf("⏱️  Timeout: %v\n", scanner.timeout)
	fmt.Printf("👥 Workers: %d\n\n", scanner.maxWorkers)

	// Phase 1: Host Discovery
	fmt.Println("Phase 1: Host Discovery")
	fmt.Println("----------------------")
	if !scanner.hostDiscovery() {
		fmt.Printf("❌ Host %s appears to be down or unreachable\n", target)
		os.Exit(1)
	}
	fmt.Printf("✅ Host %s is alive\n\n", target)

	// Phase 2: Port Scanning
	fmt.Println("Phase 2: Port Scanning")
	fmt.Println("----------------------")
	scanner.portScan(commonPorts)
	fmt.Printf("✅ Found %d open ports\n\n", len(scanner.results.OpenPorts))

	// Phase 3: Service Detection
	fmt.Println("Phase 3: Service Detection")
	fmt.Println("-------------------------")
	scanner.serviceDetection()
	fmt.Printf("✅ Identified %d services\n\n", len(scanner.results.Services))

	// Phase 4: Banner Grabbing
	fmt.Println("Phase 4: Banner Grabbing")
	fmt.Println("------------------------")
	scanner.bannerGrabbing()
	fmt.Printf("✅ Collected %d banners\n\n", len(scanner.results.Banners))

	// Phase 5: HTTP Enumeration
	fmt.Println("Phase 5: HTTP Enumeration")
	fmt.Println("------------------------")
	scanner.httpEnumeration()
	fmt.Printf("✅ Analyzed %d HTTP services\n\n", len(scanner.results.HTTPInfo))

	// Phase 6: TLS/SSL Analysis
	fmt.Println("Phase 6: TLS/SSL Analysis")
	fmt.Println("------------------------")
	scanner.tlsAnalysis()
	fmt.Printf("✅ Analyzed %d TLS services\n\n", len(scanner.results.TLSInfo))

	// Generate Report
	fmt.Println("📊 Generating Security Report")
	fmt.Println("============================")
	scanner.generateReport()
}

func (ns *NetworkScanner) hostDiscovery() bool {
	fmt.Printf("🔍 Checking if %s is reachable...\n", ns.results.Target)

	// Try ICMP ping first (may not work due to firewalls)
	conn, err := net.DialTimeout("ip4:icmp", ns.results.Target, ns.timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Try TCP connect to common ports
	testPorts := []int{80, 443, 22, 21}
	for _, port := range testPorts {
		address := fmt.Sprintf("%s:%d", ns.results.Target, port)
		conn, err := net.DialTimeout("tcp", address, ns.timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}

	return false
}

func (ns *NetworkScanner) portScan(ports []int) {
	fmt.Printf("🔍 Scanning %d ports...\n", len(ports))

	portChan := make(chan int, len(ports))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < ns.maxWorkers; i++ {
		wg.Add(1)
		go ns.portWorker(portChan, &wg)
	}

	// Send ports to scan
	for _, port := range ports {
		portChan <- port
	}
	close(portChan)

	wg.Wait()

	// Sort results by port number
	sort.Slice(ns.results.OpenPorts, func(i, j int) bool {
		return ns.results.OpenPorts[i].Port < ns.results.OpenPorts[j].Port
	})
}

func (ns *NetworkScanner) portWorker(ports <-chan int, wg *sync.WaitGroup) {
	defer wg.Done()

	for port := range ports {
		address := fmt.Sprintf("%s:%d", ns.results.Target, port)
		conn, err := net.DialTimeout("tcp", address, ns.timeout)

		if err == nil {
			conn.Close()

			portInfo := PortInfo{
				Port:     port,
				Protocol: "tcp",
				State:    "open",
				Service:  getServiceName(port),
			}

			ns.mu.Lock()
			ns.results.OpenPorts = append(ns.results.OpenPorts, portInfo)
			ns.mu.Unlock()

			fmt.Printf("  ✅ %d/tcp open (%s)\n", port, portInfo.Service)
		}
	}
}

func (ns *NetworkScanner) serviceDetection() {
	fmt.Println("🔍 Detecting services on open ports...")

	var wg sync.WaitGroup

	for _, portInfo := range ns.results.OpenPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			ns.detectService(port)
		}(portInfo.Port)
	}

	wg.Wait()
}

func (ns *NetworkScanner) detectService(port int) {
	address := fmt.Sprintf("%s:%d", ns.results.Target, port)
	conn, err := net.DialTimeout("tcp", address, ns.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(ns.timeout))

	// Send a simple probe
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	response := string(buffer[:n])
	service := identifyService(response, port)

	if service.Service != "unknown" {
		ns.mu.Lock()
		ns.results.Services = append(ns.results.Services, service)
		ns.mu.Unlock()

		fmt.Printf("  🔍 Port %d: %s %s\n", port, service.Service, service.Version)
	}
}

func (ns *NetworkScanner) bannerGrabbing() {
	fmt.Println("🔍 Grabbing service banners...")

	var wg sync.WaitGroup

	for _, portInfo := range ns.results.OpenPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			ns.grabBanner(port)
		}(portInfo.Port)
	}

	wg.Wait()
}

func (ns *NetworkScanner) grabBanner(port int) {
	address := fmt.Sprintf("%s:%d", ns.results.Target, port)
	conn, err := net.DialTimeout("tcp", address, ns.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(ns.timeout))

	// Different probes for different services
	var probe []byte
	switch port {
	case 21:
		// FTP - just connect and read banner
		probe = []byte("")
	case 22:
		// SSH - just connect and read banner
		probe = []byte("")
	case 25:
		// SMTP - send HELO
		probe = []byte("HELO test\r\n")
	case 80, 8080:
		// HTTP - send GET request
		probe = []byte("GET / HTTP/1.1\r\nHost: " + ns.results.Target + "\r\n\r\n")
	default:
		probe = []byte("GET / HTTP/1.0\r\n\r\n")
	}

	if len(probe) > 0 {
		conn.Write(probe)
	}

	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil && n == 0 {
		return
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	if len(banner) > 0 {
		bannerInfo := BannerInfo{
			Port:   port,
			Banner: banner,
		}

		ns.mu.Lock()
		ns.results.Banners = append(ns.results.Banners, bannerInfo)
		ns.mu.Unlock()

		// Truncate long banners for display
		displayBanner := banner
		if len(displayBanner) > 100 {
			displayBanner = displayBanner[:100] + "..."
		}
		fmt.Printf("  📄 Port %d banner: %s\n", port, strings.Replace(displayBanner, "\n", "\\n", -1))
	}
}

func (ns *NetworkScanner) httpEnumeration() {
	fmt.Println("🔍 Enumerating HTTP services...")

	httpPorts := []int{}
	for _, port := range ns.results.OpenPorts {
		if port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Service == "http" {
			httpPorts = append(httpPorts, port.Port)
		}
	}

	var wg sync.WaitGroup
	for _, port := range httpPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			ns.analyzeHTTP(port)
		}(port)
	}

	wg.Wait()
}

func (ns *NetworkScanner) analyzeHTTP(port int) {
	scheme := "http"
	if port == 443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ns.results.Target, port)

	client := &http.Client{
		Timeout: ns.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Extract title from HTML
	title := "No title"
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		buffer := make([]byte, 4096)
		n, _ := resp.Body.Read(buffer)
		content := string(buffer[:n])

		titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
		if matches := titleRegex.FindStringSubmatch(content); len(matches) > 1 {
			title = strings.TrimSpace(matches[1])
		}
	}

	httpInfo := HTTPInfo{
		Port:    port,
		Status:  resp.StatusCode,
		Server:  resp.Header.Get("Server"),
		Headers: make(map[string]string),
		Title:   title,
	}

	// Collect interesting headers
	interestingHeaders := []string{"Server", "X-Powered-By", "X-Framework", "Set-Cookie"}
	for _, header := range interestingHeaders {
		if value := resp.Header.Get(header); value != "" {
			httpInfo.Headers[header] = value
		}
	}

	ns.mu.Lock()
	ns.results.HTTPInfo = append(ns.results.HTTPInfo, httpInfo)
	ns.mu.Unlock()

	fmt.Printf("  🌐 Port %d HTTP: %d %s - %s\n", port, resp.StatusCode, resp.Status, title)
}

func (ns *NetworkScanner) tlsAnalysis() {
	fmt.Println("🔍 Analyzing TLS/SSL configurations...")

	var wg sync.WaitGroup
	for _, portInfo := range ns.results.OpenPorts {
		if portInfo.Port == 443 || portInfo.Port == 993 || portInfo.Port == 995 {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				ns.analyzeTLS(port)
			}(portInfo.Port)
		}
	}

	wg.Wait()
}

func (ns *NetworkScanner) analyzeTLS(port int) {
	address := fmt.Sprintf("%s:%d", ns.results.Target, port)

	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         ns.results.Target,
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: ns.timeout}, "tcp", address, config)
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	tlsInfo := TLSInfo{
		Port:            port,
		Version:         tlsVersionString(state.Version),
		Cipher:          tls.CipherSuiteName(state.CipherSuite),
		Vulnerabilities: []string{},
	}

	// Check for certificates
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.Certificate = fmt.Sprintf("CN=%s, Issuer=%s, Expires=%s",
			cert.Subject.CommonName, cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"))

		// Check for expired certificates
		if cert.NotAfter.Before(time.Now()) {
			tlsInfo.Vulnerabilities = append(tlsInfo.Vulnerabilities, "Expired certificate")
		}

		// Check for weak signature algorithms
		if cert.SignatureAlgorithm.String() == "SHA1-RSA" {
			tlsInfo.Vulnerabilities = append(tlsInfo.Vulnerabilities, "Weak SHA1 signature")
		}
	}

	// Check for weak TLS versions
	if state.Version < tls.VersionTLS12 {
		tlsInfo.Vulnerabilities = append(tlsInfo.Vulnerabilities, "Weak TLS version")
	}

	ns.mu.Lock()
	ns.results.TLSInfo = append(ns.results.TLSInfo, tlsInfo)
	ns.mu.Unlock()

	vulnStr := ""
	if len(tlsInfo.Vulnerabilities) > 0 {
		vulnStr = fmt.Sprintf(" [VULNERABILITIES: %s]", strings.Join(tlsInfo.Vulnerabilities, ", "))
	}

	fmt.Printf("  🔒 Port %d TLS: %s, %s%s\n", port, tlsInfo.Version, tlsInfo.Cipher, vulnStr)
}

func (ns *NetworkScanner) generateReport() {
	fmt.Printf("\n📊 SECURITY SCAN REPORT FOR %s\n", ns.results.Target)
	fmt.Println("=" + strings.Repeat("=", len(ns.results.Target)+28))

	// Summary
	fmt.Printf("\n📋 SUMMARY:\n")
	fmt.Printf("  • Open Ports: %d\n", len(ns.results.OpenPorts))
	fmt.Printf("  • Identified Services: %d\n", len(ns.results.Services))
	fmt.Printf("  • HTTP Services: %d\n", len(ns.results.HTTPInfo))
	fmt.Printf("  • TLS Services: %d\n", len(ns.results.TLSInfo))

	// Open Ports
	if len(ns.results.OpenPorts) > 0 {
		fmt.Printf("\n🔓 OPEN PORTS:\n")
		for _, port := range ns.results.OpenPorts {
			fmt.Printf("  • %d/%s (%s)\n", port.Port, port.Protocol, port.Service)
		}
	}

	// Services
	if len(ns.results.Services) > 0 {
		fmt.Printf("\n🔍 IDENTIFIED SERVICES:\n")
		for _, service := range ns.results.Services {
			fmt.Printf("  • Port %d: %s %s\n", service.Port, service.Service, service.Version)
		}
	}

	// HTTP Services
	if len(ns.results.HTTPInfo) > 0 {
		fmt.Printf("\n🌐 HTTP SERVICES:\n")
		for _, http := range ns.results.HTTPInfo {
			fmt.Printf("  • Port %d: %d %s\n", http.Port, http.Status, http.Title)
			if http.Server != "" {
				fmt.Printf("    Server: %s\n", http.Server)
			}
		}
	}

	// TLS Analysis
	if len(ns.results.TLSInfo) > 0 {
		fmt.Printf("\n🔒 TLS/SSL ANALYSIS:\n")
		for _, tls := range ns.results.TLSInfo {
			fmt.Printf("  • Port %d: %s\n", tls.Port, tls.Version)
			if len(tls.Vulnerabilities) > 0 {
				fmt.Printf("    ⚠️  Vulnerabilities: %s\n", strings.Join(tls.Vulnerabilities, ", "))
			}
		}
	}

	// Security Recommendations
	fmt.Printf("\n🛡️  SECURITY RECOMMENDATIONS:\n")
	ns.generateRecommendations()

	fmt.Printf("\n⚠️  DISCLAIMER: This scan is for authorized testing only.\n")
	fmt.Printf("Always ensure you have proper authorization before scanning networks.\n")
}

func (ns *NetworkScanner) generateRecommendations() {
	recommendations := []string{}

	// Check for common vulnerable ports
	vulnerablePorts := map[int]string{
		21:   "FTP - Consider using SFTP instead",
		23:   "Telnet - Use SSH instead",
		135:  "RPC - Limit access or disable if not needed",
		139:  "NetBIOS - Potential information disclosure",
		445:  "SMB - Ensure latest patches applied",
		1433: "SQL Server - Restrict access",
		3389: "RDP - Use VPN or restrict access",
	}

	for _, port := range ns.results.OpenPorts {
		if rec, exists := vulnerablePorts[port.Port]; exists {
			recommendations = append(recommendations, fmt.Sprintf("Port %d: %s", port.Port, rec))
		}
	}

	// Check TLS vulnerabilities
	for _, tls := range ns.results.TLSInfo {
		for _, vuln := range tls.Vulnerabilities {
			recommendations = append(recommendations, fmt.Sprintf("Port %d TLS: %s", tls.Port, vuln))
		}
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No major security issues detected in this scan")
	}

	for i, rec := range recommendations {
		fmt.Printf("  %d. %s\n", i+1, rec)
	}
}

// Helper functions
func getServiceName(port int) string {
	services := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		111:  "rpcbind",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		1723: "pptp",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		5900: "vnc",
		8080: "http-proxy",
	}

	if service, exists := services[port]; exists {
		return service
	}
	return "unknown"
}

func identifyService(response string, port int) ServiceInfo {
	service := ServiceInfo{
		Port:    port,
		Service: "unknown",
		Version: "",
	}

	response = strings.ToLower(response)

	// HTTP detection
	if strings.Contains(response, "http/") {
		service.Service = "http"
		if strings.Contains(response, "apache") {
			service.Version = "Apache"
		} else if strings.Contains(response, "nginx") {
			service.Version = "nginx"
		} else if strings.Contains(response, "iis") {
			service.Version = "IIS"
		}
	}

	// SSH detection
	if strings.Contains(response, "ssh-") {
		service.Service = "ssh"
		if strings.Contains(response, "openssh") {
			service.Version = "OpenSSH"
		}
	}

	// FTP detection
	if strings.Contains(response, "220 ") && port == 21 {
		service.Service = "ftp"
		if strings.Contains(response, "vsftp") {
			service.Version = "vsftpd"
		}
	}

	return service
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
