package handler

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

type Handler struct {
	logger *log.Logger
}

func New(logger *log.Logger) *Handler {
	return &Handler{
		logger: logger,
	}
}

// HealthCheck returns the health status of the service
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"ok","service":"oauth-proxy"}`)
}

// DebugCallback logs all parameters for debugging OAuth issues
func (h *Handler) DebugCallback(w http.ResponseWriter, r *http.Request) {
	h.logger.Printf("DEBUG: Received request from %s", r.RemoteAddr)
	h.logger.Printf("DEBUG: Full URL: %s", r.URL.String())
	h.logger.Printf("DEBUG: Method: %s", r.Method)
	h.logger.Printf("DEBUG: Headers: %v", r.Header)
	h.logger.Printf("DEBUG: Query parameters: %v", r.URL.Query())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{
	"debug": true,
	"url": %q,
	"method": %q,
	"query_params": %v,
	"headers": %v
}`, 
	r.URL.String(), r.Method, r.URL.Query(), r.Header)
}

// HandleCallback processes the OAuth callback from Google
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	h.logger.Printf("Received OAuth callback from %s", r.RemoteAddr)
	h.logger.Printf("Full callback URL: %s", r.URL.String()) 

	// Extract parameters from query
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	oauthError := r.URL.Query().Get("error")

	h.logger.Printf("Extracted parameters - code: %s, state: %s, error: %s",
		maskSensitiveData(code), state, oauthError)

	// Validate state parameter
	if state == "" {
		h.logger.Printf("Error: State parameter is missing")
		http.Error(w, "State parameter is missing", http.StatusBadRequest)
		return
	}

	// Decode the state to get the callback URL
	callbackURL, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		h.logger.Printf("Error: Invalid state parameter: %v", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	callback, err := url.Parse(string(callbackURL))
	if err != nil {
		h.logger.Printf("Error: Invalid callback URL in state: %v", err)
		http.Error(w, "Invalid callback URL in state", http.StatusBadRequest)
		return
	}

	h.logger.Printf("Callback destination: %s", callback.String())

	// Handle OAuth errors
	if oauthError != "" {
		h.logger.Printf("OAuth error received: %s, forwarding to backend", oauthError)
		h.redirectWithError(w, r, callback, oauthError)
		return
	}

	// If there is no error, the code should be present
	if code == "" {
		h.logger.Printf("Error: Code parameter is missing")
		h.redirectWithError(w, r, callback, "code_missing")
		return
	}

	// Redirect back to backend with code data
	h.redirectWithCode(w, r, callback, code)
}

func (h *Handler) redirectWithError(w http.ResponseWriter, r *http.Request, callback *url.URL, errorParam string) {
	query := callback.Query()
	query.Add("error", errorParam)
	callback.RawQuery = query.Encode()

	h.logger.Printf("Redirecting to backend with error: %s", callback.String())
	http.Redirect(w, r, callback.String(), http.StatusTemporaryRedirect)
}

func (h *Handler) redirectWithCode(w http.ResponseWriter, r *http.Request, callback *url.URL, codeParam string) {
	query := callback.Query()
	query.Add("code", codeParam)
	callback.RawQuery = query.Encode()

	h.logger.Printf("Redirecting to backend with code data")
	http.Redirect(w, r, callback.String(), http.StatusTemporaryRedirect)
}

// maskSensitiveData masks sensitive data for logging
func maskSensitiveData(data string) string {
	if len(data) == 0 {
		return "[EMPTY]"
	}
	if len(data) <= 8 {
		return "[REDACTED]"
	}
	return data[:4] + "..." + data[len(data)-4:]
}
