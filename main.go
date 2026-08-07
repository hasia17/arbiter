package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
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
	results = append(results, checkCookies(resp)...)
	results = append(results, checkSecurityTxt(resp))
	results = append(results, checkDNS(resp.Request.URL.Hostname()))
	results = append(results, checkSPF(resp.Request.URL.Hostname()))

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

func checkCookies(resp *http.Response) []CheckResult {
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return []CheckResult{{Name: "Cookies", Value: "none set", Pass: true}}
	}

	var results []CheckResult
	for _, c := range cookies {
		value := fmt.Sprintf("Secure=%t HttpOnly=%t SameSite=%s", c.Secure, c.HttpOnly, sameSiteName(c.SameSite))
		pass := c.Secure && c.HttpOnly
		results = append(results, CheckResult{Name: "Cookie: " + c.Name, Value: value, Pass: pass})
	}
	return results
}

func sameSiteName(s http.SameSite) string {
	switch s {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "unset"
	}
}

func checkSecurityTxt(resp *http.Response) CheckResult {
	base := resp.Request.URL
	securityTxtURL := base.Scheme + "://" + base.Host + "/.well-known/security.txt"

	txtResp, err := http.Get(securityTxtURL)
	if err != nil {
		return CheckResult{Name: "security.txt", Value: "error checking: " + err.Error(), Pass: false}
	}
	defer txtResp.Body.Close()

	if txtResp.StatusCode == http.StatusOK {
		return CheckResult{Name: "security.txt", Value: "present", Pass: true}
	}
	return CheckResult{Name: "security.txt", Value: "missing", Pass: false}
}

func checkDNS(hostname string) CheckResult {
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return CheckResult{Name: "DNS records", Value: "lookup failed: " + err.Error(), Pass: false}
	}
	return CheckResult{Name: "DNS records", Value: strings.Join(ips, ", "), Pass: true}
}

func checkSPF(hostname string) CheckResult {
	records, err := net.LookupTXT(hostname)
	if err != nil {
		return CheckResult{Name: "SPF record", Value: "lookup failed: " + err.Error(), Pass: false}
	}

	for _, r := range records {
		if strings.HasPrefix(r, "v=spf1") {
			return CheckResult{Name: "SPF record", Value: r, Pass: true}
		}
	}
	return CheckResult{Name: "SPF record", Value: "missing", Pass: false}
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
