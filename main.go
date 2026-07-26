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
	defer resp.Body.Close()

	fmt.Println("Status:", resp.Status)

	securityHeaders := []string{
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"Content-Security-Policy",
		"X-Frame-Options",
	}
	for _, name := range securityHeaders {
		checkHeader(resp.Header, name)
	}

	checkServerDisclosure(resp.Header)
}

func checkHeader(headers http.Header, name string) {
	value := headers.Get(name)
	if value == "" {
		fmt.Println(name, ": MISSING")
	} else {
		fmt.Println(name, ":", value)
	}
}

func checkServerDisclosure(headers http.Header) {
	value := headers.Get("Server")
	if value == "" {
		fmt.Println("Server disclosure: none")
	} else {
		fmt.Println("Server disclosure:", value)
	}
}

func validateURL(url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fmt.Println("Error: url must start with http:// or https://")
		os.Exit(1)
	}
}
