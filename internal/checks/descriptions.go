package checks

import "strings"

// descriptions explain each check in plain language. They live next to the
// checks so a renamed check can't silently lose its description;
// TestRunDescribesEveryCheck guards this.
var descriptions = map[string]string{
	"HTTP status":               "The response code returned by the server; 4xx and 5xx codes mean the page could not be served.",
	"Strict-Transport-Security": "Forces browsers to always use HTTPS for this site, preventing downgrade attacks. Should last at least 180 days.",
	"X-Content-Type-Options":    "Stops browsers from guessing file types, which can prevent some attacks. The only valid value is nosniff.",
	"Content-Security-Policy":   "Restricts which sources of scripts, styles and other content the page may load, reducing the impact of injection attacks.",
	"X-Frame-Options":           "Controls whether the page can be embedded in a frame on another site, helping prevent clickjacking.",
	"Referrer-Policy":           "Controls how much of the page's URL is shared with other sites when a user navigates away or loads a resource.",
	"Permissions-Policy":        "Restricts which browser features (camera, microphone, geolocation, etc.) the page is allowed to use.",
	"Server disclosure":         "Whether the Server header reveals a software version that could help an attacker find known vulnerabilities.",
	"Redirect to HTTPS":         "Checks that plain HTTP requests are redirected to the encrypted HTTPS version of the site.",
	"Certificate validity":      "Whether the TLS certificate is issued by a trusted authority and matches the site's hostname.",
	"Certificate expiry":        "How many days remain before the site's TLS certificate expires and browsers start showing warnings.",
	"TLS version":               "The encryption protocol version used; TLS 1.2 or newer is considered secure.",
	"security.txt":              "A standard file that tells security researchers how to report vulnerabilities to the site owner.",
	"DNS records":               "The IP addresses the domain name resolves to.",
	"SPF record":                "A DNS record listing which servers may send email for this domain, helping prevent email spoofing.",
	"Cookies":                   "Cookies should be marked Secure (sent only over HTTPS) and HttpOnly (hidden from JavaScript) to protect them from theft.",
}

func describe(name string) string {
	if strings.HasPrefix(name, "Cookie: ") {
		name = "Cookies"
	}
	return descriptions[name]
}
