package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/hasia17/arbiter/internal/checks"
	"github.com/hasia17/arbiter/internal/report"
)

const (
	exitOK       = 0
	exitFailures = 1 // the scan finished, but at least one check failed
	exitError    = 2 // bad usage, or the scan could not run at all
)

func main() {
	// os.Exit skips deferred calls, so all real work happens in run()
	// and main only turns its result into an exit code.
	os.Exit(run())
}

func run() int {
	target := flag.String("url", "", "URL to scan (required)")
	out := flag.String("out", "", "file name for the PDF report, written to the reports/ directory (optional)")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: arbiter -url <url> [-out report.pdf]")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *target == "" {
		flag.Usage()
		return exitError
	}
	if err := validateURL(*target); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return exitError
	}

	var path string
	if *out != "" {
		p, err := reportPath(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			return exitError
		}
		path = p
	}

	results, err := checks.Run(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error fetching url:", err)
		return exitError
	}

	failed := 0
	for _, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %s: %s\n", status, r.Name, r.Value)
	}
	fmt.Printf("\n%d of %d checks passed\n", len(results)-failed, len(results))

	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			fmt.Fprintln(os.Stderr, "Error creating reports directory:", err)
			return exitError
		}
		if err := report.WritePDF(*target, results, path); err != nil {
			fmt.Fprintln(os.Stderr, "Error writing PDF:", err)
			return exitError
		}
		fmt.Println("PDF report written to", path)
	}

	if failed > 0 {
		return exitFailures
	}
	return exitOK
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("url must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("url has no host")
	}
	return nil
}

// reportPath accepts a plain file name and places it in reports/.
// Paths are rejected so the report can't be written outside that directory.
func reportPath(name string) (string, error) {
	if name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("-out must be a file name, not a path: %q", name)
	}
	return filepath.Join("reports", name), nil
}
