package checks

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CheckResult struct {
	Name        string
	Value       string
	Pass        bool
	Description string
}

const (
	minHSTSMaxAge   = 180 * 24 * 60 * 60 // 180 days, in seconds
	certWarningDays = 14
)

// client is deliberately permissive: it accepts invalid certificates and old
// TLS versions, so that broken sites can still be scanned instead of failing
// with a connection error. Certificate validity and TLS version are reported
// as separate checks. Never reuse this client for requests that send secrets.
var client = newScanClient()

func newScanClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allCipherSuites(),
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

// allCipherSuites includes the insecure suites too, because old servers
// often support nothing else and we still want to report on them.
func allCipherSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

func Run(url string) ([]CheckResult, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	host := resp.Request.URL.Hostname()

	results := []CheckResult{
		checkHTTPStatus(resp),
		checkHSTS(resp),
		checkHeader(resp.Header, "X-Content-Type-Options", validateNoSniff),
		checkHeader(resp.Header, "Content-Security-Policy", nil),
		checkHeader(resp.Header, "X-Frame-Options", validateFrameOptions),
		checkHeader(resp.Header, "Referrer-Policy", validateReferrerPolicy),
		checkHeader(resp.Header, "Permissions-Policy", nil),
		checkServerDisclosure(resp.Header),
		checkRedirectToHTTPS(url, resp),
		checkCertValidity(resp),
		checkCertExpiry(resp),
		checkTLSVersion(resp),
	}
	results = append(results, checkCookies(resp)...)
	results = append(results,
		checkSecurityTxt(resp),
		checkDNS(host),
		checkSPF(host),
	)

	for i := range results {
		results[i].Description = describe(results[i].Name)
	}
	return results, nil
}

// checkHTTPStatus passes for 1xx-3xx responses and fails for 4xx/5xx errors.
func checkHTTPStatus(resp *http.Response) CheckResult {
	return CheckResult{Name: "HTTP status", Value: resp.Status, Pass: resp.StatusCode < 400}
}

// checkHeader fails when the header is missing. If validate is not nil, it is
// called with the header value and returns a problem description, or "" if
// the value is fine.
func checkHeader(headers http.Header, name string, validate func(string) string) CheckResult {
	value := headers.Get(name)
	if value == "" {
		return CheckResult{Name: name, Value: "MISSING", Pass: false}
	}
	if validate != nil {
		if problem := validate(value); problem != "" {
			// The problem goes first so it survives truncation in the PDF.
			return CheckResult{Name: name, Value: problem + ": " + value, Pass: false}
		}
	}
	return CheckResult{Name: name, Value: value, Pass: true}
}

func checkHSTS(resp *http.Response) CheckResult {
	const name = "Strict-Transport-Security"
	if resp.TLS == nil {
		return CheckResult{Name: name, Value: "not served over https, browsers ignore HSTS", Pass: false}
	}
	return checkHeader(resp.Header, name, validateHSTS)
}

func validateHSTS(value string) string {
	for _, directive := range strings.Split(value, ";") {
		key, val, _ := strings.Cut(strings.TrimSpace(directive), "=")
		if !strings.EqualFold(key, "max-age") {
			continue
		}
		age, err := strconv.Atoi(strings.Trim(val, `"`))
		if err != nil {
			return "invalid max-age"
		}
		if age < minHSTSMaxAge {
			return "max-age shorter than 180 days"
		}
		return ""
	}
	return "max-age missing"
}

func validateNoSniff(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		return ""
	}
	return `expected "nosniff"`
}

func validateFrameOptions(value string) string {
	v := strings.TrimSpace(value)
	if strings.EqualFold(v, "DENY") || strings.EqualFold(v, "SAMEORIGIN") {
		return ""
	}
	return "expected DENY or SAMEORIGIN"
}

func validateReferrerPolicy(value string) string {
	for _, policy := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(policy), "unsafe-url") {
			return "unsafe-url leaks full URLs"
		}
	}
	return ""
}

// versionPattern matches a version number after a slash, e.g. "nginx/1.18.0"
// or "Microsoft-IIS/10.0". A bare product name like "nginx" is not a problem.
var versionPattern = regexp.MustCompile(`/\s*v?\d`)

func checkServerDisclosure(headers http.Header) CheckResult {
	const name = "Server disclosure"
	value := headers.Get("Server")
	if value == "" {
		return CheckResult{Name: name, Value: "none", Pass: true}
	}
	if versionPattern.MatchString(value) {
		return CheckResult{Name: name, Value: "version exposed: " + value, Pass: false}
	}
	return CheckResult{Name: name, Value: value + " (no version)", Pass: true}
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

// checkCertValidity does the verification the scan client skips: the chain
// must lead to a trusted root and the certificate must match the hostname.
func checkCertValidity(resp *http.Response) CheckResult {
	const name = "Certificate validity"
	if resp.TLS == nil {
		return CheckResult{Name: name, Value: "n/a, not https", Pass: true}
	}
	certs := resp.TLS.PeerCertificates
	if len(certs) == 0 {
		return CheckResult{Name: name, Value: "no certificate presented", Pass: false}
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{
		DNSName:       resp.Request.URL.Hostname(),
		Intermediates: intermediates,
	})
	if err != nil {
		// Some x509 errors end with an empty detail, e.g. "...not yet valid: ".
		reason := strings.TrimSuffix(err.Error(), ": ")
		return CheckResult{Name: name, Value: reason, Pass: false}
	}
	return CheckResult{Name: name, Value: "trusted, matches hostname", Pass: true}
}

func checkCertExpiry(resp *http.Response) CheckResult {
	const name = "Certificate expiry"
	if resp.TLS == nil {
		return CheckResult{Name: name, Value: "n/a, not https", Pass: true}
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return CheckResult{Name: name, Value: "no certificate presented", Pass: false}
	}

	notAfter := resp.TLS.PeerCertificates[0].NotAfter
	if !time.Now().Before(notAfter) {
		return CheckResult{Name: name, Value: "expired on " + notAfter.Format("2006-01-02"), Pass: false}
	}

	daysLeft := int(time.Until(notAfter).Hours() / 24)
	if daysLeft < certWarningDays {
		return CheckResult{Name: name, Value: fmt.Sprintf("%d days left, renew soon", daysLeft), Pass: false}
	}
	return CheckResult{Name: name, Value: fmt.Sprintf("%d days left", daysLeft), Pass: true}
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
	cookies := collectCookies(resp)
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

// collectCookies returns cookies set by every response in the redirect chain,
// not only the final one. resp.Request.Response points to the redirect
// response that led to this request, so we can walk the chain backwards.
// If a cookie is set more than once, the latest value wins.
func collectCookies(resp *http.Response) []*http.Cookie {
	var chain []*http.Response
	for r := resp; r != nil; {
		chain = append(chain, r)
		if r.Request == nil {
			break
		}
		r = r.Request.Response
	}

	var order []string
	byName := map[string]*http.Cookie{}
	for i := len(chain) - 1; i >= 0; i-- { // oldest response first
		for _, c := range chain[i].Cookies() {
			if _, seen := byName[c.Name]; !seen {
				order = append(order, c.Name)
			}
			byName[c.Name] = c
		}
	}

	cookies := make([]*http.Cookie, 0, len(order))
	for _, name := range order {
		cookies = append(cookies, byName[name])
	}
	return cookies
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

	txtResp, err := client.Get(securityTxtURL)
	if err != nil {
		return CheckResult{Name: "security.txt", Value: "error checking: " + err.Error(), Pass: false}
	}
	defer txtResp.Body.Close()

	if txtResp.StatusCode != http.StatusOK {
		return CheckResult{Name: "security.txt", Value: "missing", Pass: false}
	}

	// Many sites answer every path with 200 and an HTML page, so a 200 alone
	// does not prove the file exists. The standard requires text/plain.
	contentType := txtResp.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "text/plain") {
		if contentType == "" {
			contentType = "none"
		}
		return CheckResult{Name: "security.txt", Value: "not plain text (Content-Type: " + contentType + ")", Pass: false}
	}
	return CheckResult{Name: "security.txt", Value: "present", Pass: true}
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
