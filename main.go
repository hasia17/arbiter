package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "", "URL to scan (required)")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run main.go -url <url>")
		os.Exit(1)
	}

	validateURL(*url)
	fetchURL(*url)
}

type CheckResult struct {
	Name  string
	Value string
	Pass  bool
}

func fetchURL(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching url:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)

	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	var results []CheckResult
	for _, name := range securityHeaders {
		results = append(results, checkHeader(resp.Header, name))
	}
	results = append(results, checkServerDisclosure(resp.Header))
	results = append(results, checkRedirectToHTTPS(url, resp))
	results = append(results, checkCertExpiry(resp))
	results = append(results, checkTLSVersion(resp))

	for _, r := range results {
		fmt.Println(r.Name, ":", r.Value)
	}
}

func checkRedirectToHTTPS(originalURL string, resp *http.Response) CheckResult {
	finalURL := resp.Request.URL.String()
	if strings.HasPrefix(originalURL, "https://") {
		return CheckResult{Name: "Redirect to HTTPS", Value: "n/a, already https", Pass: true}
	}
	if strings.HasPrefix(finalURL, "https://") {
		return CheckResult{Name: "Redirect to HTTPS", Value: "yes", Pass: true}
	}
	return CheckResult{Name: "Redirect to HTTPS", Value: "no", Pass: false}
}

func checkHeader(headers http.Header, name string) CheckResult {
	value := headers.Get(name)
	if value == "" {
		return CheckResult{Name: name, Value: "MISSING", Pass: false}
	}
	return CheckResult{Name: name, Value: value, Pass: true}
}

func checkCertExpiry(resp *http.Response) CheckResult {
	if resp.TLS == nil {
		return CheckResult{Name: "Certificate expiry", Value: "n/a, not https", Pass: true}
	}

	cert := resp.TLS.PeerCertificates[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	value := fmt.Sprintf("%d days left", daysLeft)
	return CheckResult{Name: "Certificate expiry", Value: value, Pass: daysLeft > 0}
}

func checkTLSVersion(resp *http.Response) CheckResult {
	if resp.TLS == nil {
		return CheckResult{Name: "TLS version", Value: "n/a, not https", Pass: true}
	}

	version := resp.TLS.Version
	name := tls.VersionName(version)
	return CheckResult{Name: "TLS version", Value: name, Pass: version >= tls.VersionTLS12}
}

func checkServerDisclosure(headers http.Header) CheckResult {
	value := headers.Get("Server")
	if value == "" {
		return CheckResult{Name: "Server disclosure", Value: "none", Pass: true}
	}
	return CheckResult{Name: "Server disclosure", Value: value, Pass: false}
}

func validateURL(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println("Error: url must start with http:// or https://")
		os.Exit(1)
	}
}
