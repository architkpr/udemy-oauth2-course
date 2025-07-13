package main

import (
	"encoding/json"
	"os"
)

type Config struct {
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	Issuer       string   `json:"issuer"`
	AuthURI      string   `json:"authURI"`
	TokenURI     string   `json:"tokenURI"`
	RedirectURI  string   `json:"redirectURI"`
	UserInfoURI  string   `json:"userInfoURI"`
	TokenInfoURI string   `json:"tokenInfoURI"`
	Scopes       []string `json:"scopes"`
}

// LoadConfig loads the configuration from a JSON file at the given path
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
