package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <url>")
		os.Exit(1)
	}

	validateURL(os.Args[1])
	fetchURL(os.Args[1])
}

func fetchURL(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching url:", err)
		os.Exit(1)
	}

	fmt.Println("Status:", resp.Status)
}

func validateURL(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println("Error: url must start with http:// or https://")
		os.Exit(1)
	}
}
