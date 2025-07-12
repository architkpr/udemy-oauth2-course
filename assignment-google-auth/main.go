package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func doAuth(cfg *Config) {
	redirectURL, err := url.Parse(cfg.RedirectURI)
	if err != nil {
		log.Fatalf("Invalid redirect URI: %v", err)
	}

	paramsCh := make(chan url.Values) // Channel to receive response from auth request

	// Start HTTP server in a goroutine
	server := &http.Server{Addr: redirectURL.Host}
	http.HandleFunc(redirectURL.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		fmt.Fprintf(w, "Received! You can close this window.")
		paramsCh <- q // Send to channel so we can close the server
	})
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=state123",
		cfg.AuthURI,
		cfg.ClientID,
		url.QueryEscape(cfg.RedirectURI),
		urlQueryEscapeScopes(cfg.Scopes),
	)

	fmt.Printf("Open the following URL in your browser to authenticate:\n%s\n", authURL)

	// Wait for the query params from the redirect
	params := <-paramsCh
	fmt.Println("Received query parameters:")
	for k, v := range params {
		fmt.Printf("%s: %s\n", k, v)
	}

	_ = server.Close()
}

func urlQueryEscapeScopes(scopes []string) string {
	return url.QueryEscape(strings.Join(scopes, " "))
}

func main() {
	config := flag.String("config", "", "Path to config JSON file")
	flag.Parse()

	if *config == "" {
		log.Fatal("config flag (path to config JSON) is required")
	}

	cfg, err := LoadConfig(*config)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	doAuth(cfg)
}
