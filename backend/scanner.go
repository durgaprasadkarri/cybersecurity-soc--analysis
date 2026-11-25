package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanRequest struct {
	Target    string `json:"target"`
	StartPort int    `json:"start_port"`
	EndPort   int    `json:"end_port"`
}

type ScanResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "Method not allowed"})
		return
	}

	// Authentication protection
	if _, ok := requireAuth(w, r); !ok {
		return
	}

	var request ScanRequest

	if err := decodeJSON(w, r, &request); err != nil {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{"error": "Invalid JSON request"})
		return
	}

	// Validate target IP
	ip := net.ParseIP(strings.TrimSpace(request.Target))

	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		jsonResponse(w, http.StatusBadRequest,
			map[string]string{
				"error": "Only localhost and private IP addresses are allowed",
			})
		return
	}

	// Validate port range
	if request.StartPort < 1 ||
		request.EndPort > 65535 ||
		request.StartPort > request.EndPort {

		jsonResponse(w, http.StatusBadRequest,
			map[string]string{
				"error": "Valid port range is 1-65535",
			})
		return
	}

	// Worker configuration
	const workerCount = 128

	ports := make(chan int, workerCount)
	results := make(chan ScanResult, workerCount)

	var workers sync.WaitGroup

	// Start workers
	for i := 0; i < workerCount; i++ {
		workers.Add(1)

		go func() {
			defer workers.Done()

			for port := range ports {
				address := net.JoinHostPort(
					ip.String(),
					strconv.Itoa(port),
				)

				connection, err := net.DialTimeout(
					"tcp",
					address,
					500*time.Millisecond,
				)

				if err != nil {
					continue
				}

				version := detectServiceVersion(connection, port)

				_ = connection.Close()

				results <- ScanResult{
					Port:     port,
					Protocol: "TCP",
					State:    "Open",
					Service:  getServiceName(port),
					Version:  version,
				}
			}
		}()
	}

	// Send requested ports to workers
	for port := request.StartPort; port <= request.EndPort; port++ {
		ports <- port
	}

	close(ports)

	// Wait for all workers
	workers.Wait()
	close(results)

	// Collect results
	var openPorts []ScanResult

	for result := range results {
		openPorts = append(openPorts, result)
	}

	// Sort ports
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].Port < openPorts[j].Port
	})

	// Save security event
	logSecurityEvent(
		0,
		"Authenticated User",
		"PORT_SCAN",
		"TCP port scan completed. Target: "+ip.String()+
			", Ports checked: "+strconv.Itoa(request.EndPort-request.StartPort+1)+
			", Open ports: "+strconv.Itoa(len(openPorts)),
		ip.String(),
		"SUCCESS",
	)

	// Return JSON response
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"target":        ip.String(),
		"start_port":    request.StartPort,
		"end_port":      request.EndPort,
		"total_scanned": request.EndPort - request.StartPort + 1,
		"open_ports":    openPorts,
		"total_found":   len(openPorts),
	})
}

// Detect service version using a limited service banner request.
func detectServiceVersion(connection net.Conn, port int) string {
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))

	switch port {
	case 22, 21, 25, 110, 143:
		// Services that commonly send banners automatically.

	case 80, 8080, 8000:
		_, _ = fmt.Fprint(connection,
			"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")

	case 443, 8443:
		return "TLS detected; version requires TLS handshake"

	default:
		return "Not detected"
	}

	buffer := make([]byte, 1024)

	n, err := connection.Read(buffer)
	if err != nil || n == 0 {
		return "Not detected"
	}

	banner := strings.TrimSpace(string(buffer[:n]))

	banner = strings.ReplaceAll(banner, "\r", " ")
	banner = strings.ReplaceAll(banner, "\n", " ")

	if len(banner) > 150 {
		banner = banner[:150]
	}

	if banner == "" {
		return "Not detected"
	}

	return banner
}

// Identify common services by port.
func getServiceName(port int) string {
	services := map[int]string{
		20:    "FTP Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP",
		68:    "DHCP",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		135:   "MS RPC",
		139:   "NetBIOS",
		143:   "IMAP",
		161:   "SNMP",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		587:   "SMTP Submission",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "Microsoft SQL Server",
		1521:  "Oracle",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP Proxy",
		8443:  "HTTPS Alternative",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}

	if service, exists := services[port]; exists {
		return service
	}

	return "Unknown"
}
