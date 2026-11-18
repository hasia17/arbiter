package checks

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheckHTTPStatus(t *testing.T) {
	tests := []struct {
		code int
		pass bool
	}{
		{200, true},
		{301, true},
		{404, false},
		{500, false},
	}
	for _, tt := range tests {
		resp := &http.Response{StatusCode: tt.code, Status: http.StatusText(tt.code)}
		got := checkHTTPStatus(resp)
		if got.Pass != tt.pass {
			t.Errorf("status %d: Pass = %v, want %v", tt.code, got.Pass, tt.pass)
		}
	}
}

func TestCheckHeader(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "DENY")

	present := checkHeader(h, "X-Frame-Options", nil)
	if !present.Pass || present.Value != "DENY" {
		t.Errorf("present header: got %+v", present)
	}

	missing := checkHeader(h, "Content-Security-Policy", nil)
	if missing.Pass || missing.Value != "MISSING" {
		t.Errorf("missing header: got %+v", missing)
	}

	invalid := checkHeader(h, "X-Frame-Options", func(string) string { return "bad value" })
	if invalid.Pass || !strings.HasPrefix(invalid.Value, "bad value") {
		t.Errorf("invalid header: got %+v", invalid)
	}
}

func TestValidators(t *testing.T) {
	tests := []struct {
		name     string
		validate func(string) string
		value    string
		ok       bool
	}{
		{"HSTS one year", validateHSTS, "max-age=31536000; includeSubDomains", true},
		{"HSTS quoted", validateHSTS, `max-age="31536000"`, true},
		{"HSTS disabled", validateHSTS, "max-age=0", false},
		{"HSTS too short", validateHSTS, "max-age=86400", false},
		{"HSTS no max-age", validateHSTS, "includeSubDomains", false},
		{"HSTS garbage", validateHSTS, "max-age=abc", false},

		{"nosniff", validateNoSniff, "nosniff", true},
		{"nosniff uppercase", validateNoSniff, "NOSNIFF", true},
		{"nosniff wrong", validateNoSniff, "sniff-away", false},

		{"frame DENY", validateFrameOptions, "DENY", true},
		{"frame sameorigin", validateFrameOptions, "sameorigin", true},
		{"frame ALLOWALL", validateFrameOptions, "ALLOWALL", false},

		{"referrer strict", validateReferrerPolicy, "strict-origin-when-cross-origin", true},
		{"referrer unsafe", validateReferrerPolicy, "no-referrer, unsafe-url", false},
	}
	for _, tt := range tests {
		problem := tt.validate(tt.value)
		if (problem == "") != tt.ok {
			t.Errorf("%s: %q -> problem %q, want ok=%v", tt.name, tt.value, problem, tt.ok)
		}
	}
}

func TestCheckHSTSOverPlainHTTP(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=31536000")
	if got := checkHSTS(&http.Response{Header: h}); got.Pass {
		t.Errorf("HSTS over plain http should fail, got %+v", got)
	}
}

func TestCheckServerDisclosure(t *testing.T) {
	tests := []struct {
		server string
		pass   bool
	}{
		{"", true},
		{"github.com", true},
		{"nginx", true},
		{"cloudflare", true},
		{"nginx/1.18.0", false},
		{"Apache/2.4.41 (Ubuntu)", false},
		{"Microsoft-IIS/10.0", false},
	}
	for _, tt := range tests {
		h := http.Header{}
		if tt.server != "" {
			h.Set("Server", tt.server)
		}
		if got := checkServerDisclosure(h); got.Pass != tt.pass {
			t.Errorf("Server %q: Pass = %v, want %v", tt.server, got.Pass, tt.pass)
		}
	}
}

func TestCheckRedirectToHTTPS(t *testing.T) {
	respTo := func(finalURL string) *http.Response {
		u, _ := url.Parse(finalURL)
		return &http.Response{Request: &http.Request{URL: u}}
	}

	tests := []struct {
		name     string
		original string
		final    string
		pass     bool
	}{
		{"already https", "https://example.com", "https://example.com", true},
		{"redirected", "http://example.com", "https://example.com", true},
		{"stays on http", "http://example.com", "http://example.com", false},
	}
	for _, tt := range tests {
		got := checkRedirectToHTTPS(tt.original, respTo(tt.final))
		if got.Pass != tt.pass {
			t.Errorf("%s: Pass = %v, want %v", tt.name, got.Pass, tt.pass)
		}
	}
}

func TestCheckCertValidity(t *testing.T) {
	if got := checkCertValidity(&http.Response{}); !got.Pass {
		t.Errorf("not https should be n/a, got %+v", got)
	}

	noCerts := &http.Response{TLS: &tls.ConnectionState{}}
	if got := checkCertValidity(noCerts); got.Pass {
		t.Errorf("no certificates should fail, got %+v", got)
	}

	// httptest's TLS server uses a self-signed certificate, which is exactly
	// the kind of certificate a browser would reject.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("scan client should accept self-signed certs: %v", err)
	}
	resp.Body.Close()

	if got := checkCertValidity(resp); got.Pass {
		t.Errorf("self-signed certificate should fail, got %+v", got)
	}
}

func TestCheckCertExpiry(t *testing.T) {
	withCert := func(notAfter time.Time) *http.Response {
		return &http.Response{TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{NotAfter: notAfter}},
		}}
	}
	day := 24 * time.Hour

	tests := []struct {
		name string
		resp *http.Response
		pass bool
	}{
		{"not https", &http.Response{}, true},
		{"no certificates", &http.Response{TLS: &tls.ConnectionState{}}, false},
		{"valid", withCert(time.Now().Add(60 * day)), true},
		{"expires soon", withCert(time.Now().Add(5 * day)), false},
		{"expires in hours", withCert(time.Now().Add(3 * time.Hour)), false},
		{"expired", withCert(time.Now().Add(-day)), false},
	}
	for _, tt := range tests {
		got := checkCertExpiry(tt.resp)
		if got.Pass != tt.pass {
			t.Errorf("%s: Pass = %v, want %v (value %q)", tt.name, got.Pass, tt.pass, got.Value)
		}
	}
}

func TestCheckTLSVersion(t *testing.T) {
	tests := []struct {
		version uint16
		pass    bool
	}{
		{tls.VersionTLS10, false},
		{tls.VersionTLS11, false},
		{tls.VersionTLS12, true},
		{tls.VersionTLS13, true},
	}
	for _, tt := range tests {
		resp := &http.Response{TLS: &tls.ConnectionState{Version: tt.version}}
		got := checkTLSVersion(resp)
		if got.Pass != tt.pass {
			t.Errorf("%s: Pass = %v, want %v", got.Value, got.Pass, tt.pass)
		}
	}
}

func TestCheckCookies(t *testing.T) {
	none := checkCookies(&http.Response{Header: http.Header{}})
	if len(none) != 1 || !none[0].Pass {
		t.Errorf("no cookies: got %+v", none)
	}

	h := http.Header{}
	h.Add("Set-Cookie", "good=1; Secure; HttpOnly; SameSite=Strict")
	h.Add("Set-Cookie", "bad=1")
	got := checkCookies(&http.Response{Header: h})

	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	if !got[0].Pass || got[0].Name != "Cookie: good" {
		t.Errorf("secure cookie: got %+v", got[0])
	}
	if got[1].Pass || got[1].Name != "Cookie: bad" {
		t.Errorf("insecure cookie: got %+v", got[1])
	}
}

func TestCheckCookiesAcrossRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "1"})
		http.SetCookie(w, &http.Cookie{Name: "shared", Value: "old"})
		http.Redirect(w, r, "/end", http.StatusFound)
	})
	mux.HandleFunc("/end", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "shared", Value: "new", Secure: true, HttpOnly: true})
		http.SetCookie(w, &http.Cookie{Name: "final", Value: "1"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := client.Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := checkCookies(resp)
	var names []string
	for _, r := range got {
		names = append(names, r.Name)
	}
	want := "Cookie: session,Cookie: shared,Cookie: final"
	if strings.Join(names, ",") != want {
		t.Fatalf("cookies = %v, want %s", names, want)
	}
	if !got[1].Pass {
		t.Errorf("shared cookie should use the latest (secure) value, got %+v", got[1])
	}
}

func TestCheckSecurityTxt(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		pass    bool
	}{
		{"plain text file", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/security.txt" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte("Contact: mailto:security@example.com\n"))
		}, true},
		{"not found", http.NotFound, false},
		{"html for every path", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("<!doctype html><html><body>app</body></html>"))
		}, false},
	}
	for _, tt := range tests {
		srv := httptest.NewServer(tt.handler)
		u, _ := url.Parse(srv.URL)
		got := checkSecurityTxt(&http.Response{Request: &http.Request{URL: u}})
		srv.Close()

		if got.Pass != tt.pass {
			t.Errorf("%s: Pass = %v, want %v (value %q)", tt.name, got.Pass, tt.pass, got.Value)
		}
	}
}

func TestRunDescribesEveryCheck(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "c", Value: "1"})
	}))
	defer srv.Close()

	results, err := Run(srv.URL)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, r := range results {
		if r.Description == "" {
			t.Errorf("check %q has no description", r.Name)
		}
	}
}
