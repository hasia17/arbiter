package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-pdf/fpdf"
	"github.com/hasia17/arbiter/internal/checks"
)

func newTestPDF() *fpdf.Fpdf {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "", 9)
	return pdf
}

func TestTruncateLinesShortText(t *testing.T) {
	lines := truncateLines(newTestPDF(), "short", 100, 3)
	if len(lines) != 1 || lines[0] != "short" {
		t.Errorf("got %q", lines)
	}
}

func TestTruncateLinesEmptyText(t *testing.T) {
	lines := truncateLines(newTestPDF(), "", 100, 3)
	if len(lines) != 1 {
		t.Errorf("expected one empty line, got %q", lines)
	}
}

func TestTruncateLinesZeroMax(t *testing.T) {
	if lines := truncateLines(newTestPDF(), "text", 100, 0); len(lines) != 0 {
		t.Errorf("expected no lines, got %q", lines)
	}
}

func TestTruncateLinesLongText(t *testing.T) {
	pdf := newTestPDF()
	const width = 50.0
	text := strings.Repeat("default-src 'self' https://cdn.example.com ", 20)

	lines := truncateLines(pdf, text, width, 2)

	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %q", len(lines), lines)
	}
	last := lines[len(lines)-1]
	if !strings.HasSuffix(last, "...") {
		t.Errorf("last line should end with ..., got %q", last)
	}
	for _, l := range lines {
		if w := pdf.GetStringWidth(l); w > width {
			t.Errorf("line %q is %.1fmm wide, max %.1fmm", l, w, width)
		}
	}
}

func TestTruncateLinesLongWord(t *testing.T) {
	pdf := newTestPDF()
	const width = 30.0
	word := strings.Repeat("x", 200)

	lines := truncateLines(pdf, word, width, 100)
	if len(lines) < 2 {
		t.Fatalf("a word wider than the line should be broken, got %q", lines)
	}
	if strings.Join(lines, "") != word {
		t.Errorf("breaking a word must not lose characters")
	}
}

func TestTruncateLinesNonASCII(t *testing.T) {
	pdf := newTestPDF()
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	// Used to panic inside fpdf's SplitText.
	lines := truncateLines(pdf, tr(strings.Repeat("zażółć gęślą jaźń café ", 20)), 50, 2)
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %q", lines)
	}
}

func TestWritePDF(t *testing.T) {
	results := []checks.CheckResult{
		{Name: "HTTP status", Value: "200 OK", Pass: true, Description: "Status."},
		{Name: "Content-Security-Policy", Value: strings.Repeat("script-src 'self' ", 50), Pass: true},
		{Name: "Cookie: " + strings.Repeat("very_long_cookie_name_", 10), Value: "Secure=false", Pass: false},
		{Name: "Server disclosure", Value: "zażółć gęślą jaźń", Pass: false},
	}
	// Enough cards to force a page break.
	for i := 0; i < 20; i++ {
		results = append(results, checks.CheckResult{Name: "Cookie: c", Value: "Secure=false", Pass: false})
	}

	path := filepath.Join(t.TempDir(), "report.pdf")
	if err := WritePDF("https://example.com/ścieżka", results, path); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	if info.Size() == 0 {
		t.Error("report file is empty")
	}
}
