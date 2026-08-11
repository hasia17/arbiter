package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hasia17/arbiter/internal/checks"
)

func main() {
	url := flag.String("url", "", "URL to scan (required)")
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
}

func validateURL(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println("Error: url must start with http:// or https://")
		os.Exit(1)
	}
}
