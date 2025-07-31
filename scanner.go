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

// Extended port list for comprehensive scanning
var extendedPorts = []int{
	1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502, 9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
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
		fmt.Println("Usage: ./scanner <target_ip_or_domain> [options]")
		fmt.Println("Example: ./scanner 192.168.1.1")
		fmt.Println("Example: ./scanner scanme.nmap.org")
		fmt.Println("Options:")
		fmt.Println("  -extended : Use extended port list (1000+ ports)")
		fmt.Println("  -fast     : Fast scan (top 100 ports only)")
		os.Exit(1)
	}

	target := os.Args[1]

	// Parse command line options
	portsToScan := commonPorts
	if len(os.Args) > 2 {
		for _, arg := range os.Args[2:] {
			switch arg {
			case "-extended":
				portsToScan = extendedPorts
				fmt.Println("🔍 Using extended port list (1000+ ports)")
			case "-fast":
				portsToScan = []int{21, 22, 23, 25, 53, 80, 135, 139, 443, 445} // Top 10 most common
				fmt.Println("⚡ Using fast scan (top 10 ports)")
			}
		}
	}

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
	scanner.portScan(portsToScan)
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

	// Special handling for localhost/127.0.0.1
	if ns.results.Target == "localhost" || ns.results.Target == "127.0.0.1" || ns.results.Target == "::1" {
		fmt.Printf("🏠 Localhost detected - skipping ping, proceeding to port scan\n")
		return true
	}

	// Try ICMP ping first (may not work due to firewalls)
	conn, err := net.DialTimeout("ip4:icmp", ns.results.Target, ns.timeout)
	if err == nil {
		conn.Close()
		return true
	}

	// Try TCP connect to common ports
	testPorts := []int{80, 443, 22, 21, 25, 53, 111, 135, 139, 445, 993, 995, 3389, 5432, 3306}
	fmt.Printf("🔍 Testing connectivity to common ports...\n")

	for _, port := range testPorts {
		address := fmt.Sprintf("%s:%d", ns.results.Target, port)
		conn, err := net.DialTimeout("tcp", address, time.Second*1) // Shorter timeout for discovery
		if err == nil {
			conn.Close()
			fmt.Printf("✅ Found open port %d during discovery\n", port)
			return true
		}
	}

	// Final attempt with DNS resolution check
	_, err = net.LookupHost(ns.results.Target)
	if err == nil {
		fmt.Printf("✅ Host resolves in DNS, proceeding with scan\n")
		return true
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
