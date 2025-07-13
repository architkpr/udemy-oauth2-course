package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func queryTokenInfo(tokenInfoURI, idToken string) {
	req, err := http.NewRequest("GET", tokenInfoURI+"?id_token="+url.QueryEscape(idToken), nil)
	if err != nil {
		log.Fatalf("Failed to create tokeninfo request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to query tokeninfo endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read tokeninfo response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Tokeninfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Tokeninfo response:\n%s\n", string(body))
}

// Query the userinfo endpoint using the provided idToken as a Bearer token
func queryUserInfo(userInfoURI, accessToken string) {
	req, err := http.NewRequest("GET", userInfoURI, nil)
	if err != nil {
		log.Fatalf("Failed to create userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("Failed to query userinfo endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read userinfo response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	fmt.Printf("Userinfo response:\n%s\n", string(body))
}

func exchangeCodeForTokens(code string, cfg *Config) (string, string) {
	// Prepare the token request data
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", cfg.RedirectURI)

	// Make the token request
	resp, err := http.PostForm(cfg.TokenURI, data)
	if err != nil {
		log.Fatalf("Failed to exchange code for tokens: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read token response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the token response
	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		log.Fatalf("Failed to parse token response: %v", err)
	}

	return tokenResp.AccessToken, tokenResp.IDToken
}

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

	// Extract the authorization code
	code := params.Get("code")
	if code == "" {
		log.Fatal("No authorization code received")
	}

	// Exchange the code for tokens
	accessToken, idToken := exchangeCodeForTokens(code, cfg)

	fmt.Println("\n=== Token Exchange Successful ===")
	fmt.Printf("Access Token: %s\n", accessToken)
	claims := decodeJWT(idToken)
	for claim, value := range claims {
		fmt.Println(claim, value)
	}

	// Query UserInfo Endpoint
	queryUserInfo(cfg.UserInfoURI, accessToken)

	// Query TokenInfo Endpoint
	queryTokenInfo(cfg.TokenInfoURI, idToken)

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
