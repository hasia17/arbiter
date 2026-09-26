package main

import (
	"flag"

	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hasia17/arbiter/internal/checks"
	"github.com/hasia17/arbiter/internal/report"
)

func main() {
	url := flag.String("url", "", "URL to scan (required)")
	out := flag.String("out", "", "path to write PDF report (optional)")
	flag.Parse()

	if *url == "" {
		fmt.Println("Usage: go run main.go -url <url>")
		os.Exit(1)
	}

	validateURL(*url)

	results, err := checks.Run(*url)
	if err != nil {
		fmt.Println("Error fetching url:", err)
		os.Exit(1)
	}

	for _, r := range results {
		fmt.Println(r.Name, ":", r.Value)
	}

	if *out != "" {
		if err := os.MkdirAll("reports", 0755); err != nil {
			fmt.Println("Error creating reports directory:", err)
			os.Exit(1)
		}
		path := filepath.Join("reports", *out)

		if err := report.WritePDF(*url, results, path); err != nil {
			fmt.Println("Error writing PDF:", err)
			os.Exit(1)
		}
		fmt.Println("PDF report written to", path)
	}
}

func validateURL(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println("Error: url must start with http:// or https://")
		os.Exit(1)
	}
}
