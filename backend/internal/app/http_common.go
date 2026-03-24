package app

import (
	"encoding/json"
	"net/http"
	"os"
)

func writeJSON(w http.ResponseWriter, status int, code, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jsonResp{Code: code, Message: message, Data: data})
}

func statusForCode(code string) int {
	switch code {
	case "AUTH_HEADER_MISSING", "AUTH_INVALID_APP", "AUTH_SIGNATURE_INVALID", "AUTH_TIMESTAMP_INVALID", "AUTH_TIMESTAMP_EXPIRED", "AUTH_REPLAY_DETECTED":
		return http.StatusUnauthorized
	case "BANNED":
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
