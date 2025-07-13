package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Decode jwt to view claims
func decodeJWT(jwt string) []string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return []string{"Invalid JWT format"}
	}

	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return []string{"Failed to decode JWT payload: " + err.Error()}
	}

	// Unmarshal into a map to get all claims
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(decoded, &claimsMap); err != nil {
		return []string{"Failed to unmarshal JWT payload: " + err.Error()}
	}

	// Format claims as "key: value"
	var claims []string
	for k, v := range claimsMap {
		claims = append(claims, k+": "+fmt.Sprintf("%v", v))
	}
	return claims
}
