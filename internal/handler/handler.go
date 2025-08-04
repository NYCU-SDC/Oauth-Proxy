package handler

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"net/http"
	"net/url"
)

// claims defines contextual information for an OAuth transaction.
// It is encoded into the 'state' parameter as a signed JWT to preserve integrity and authenticity.
type claims struct {
	// Service is the logical service requesting authentication (e.g., "core-system", "clustron").
	Service string

	// Environment represents the environment or deployment context (e.g., "pr-12", "staging").
	Environment string

	// CallbackURL is the backend endpoint to receive the OAuth authorization code.
	// It must be an internal service endpoint, not exposed to users.
	CallbackURL string

	// RedirectURL is the final URL to send the user to after authentication completes.
	// This is typically a user-facing frontend page.
	RedirectURL string

	jwt.RegisteredClaims
}

type Handler struct {
	token  string
	logger *log.Logger
}

func New(token string, logger *log.Logger) *Handler {
	return &Handler{
		token:  token,
		logger: logger,
	}
}

// HealthCheck returns the health status of the service
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, `{"status":"ok","service":"oauth-proxy"}`)
}

// HandleCallback processes the OAuth callback from Google
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	h.logger.Printf("Received OAuth callback from %s", r.RemoteAddr)

	// Extract parameters from query
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	oauthError := r.URL.Query().Get("error")

	if oauthError != "" {
		h.logger.Printf("OAuth error received: %s", oauthError)
	}

	// Validate state parameter
	if state == "" {
		h.logger.Printf("Error: State parameter is missing")
		http.Error(w, "State parameter is missing", http.StatusBadRequest)
		return
	}

	// Decode the state to get the callback URL
	jwtClaims, err := h.parseJWT(state)
	if err != nil {
		h.logger.Printf("Error: Failed to parse JWT from state: %v", err)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	h.logger.Printf("Processing OAuth proxy for service: %s, environment: %s, callback URL: %s, redirect URL: %s",
		jwtClaims.Service, jwtClaims.Environment, jwtClaims.CallbackURL, jwtClaims.RedirectURL)

	callback, err := url.Parse(jwtClaims.CallbackURL)
	if err != nil {
		h.logger.Printf("Error: Invalid callback URL in state: %v", err)
		http.Error(w, "Invalid callback URL in state", http.StatusBadRequest)
		return
	}

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
	h.redirectWithCode(w, r, callback, jwtClaims.RedirectURL, code)
}

func (h *Handler) parseJWT(state string) (*claims, error) {
	var c claims
	token, err := jwt.ParseWithClaims(state, &c, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.token), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	return &c, nil
}

func (h *Handler) redirectWithError(w http.ResponseWriter, r *http.Request, callback *url.URL, errorParam string) {
	query := callback.Query()
	query.Add("error", errorParam)
	callback.RawQuery = query.Encode()

	h.logger.Printf("Redirecting to backend with error: %s", callback.String())
	http.Redirect(w, r, callback.String(), http.StatusTemporaryRedirect)
}

func (h *Handler) redirectWithCode(w http.ResponseWriter, r *http.Request, callback *url.URL, redirectParam string, codeParam string) {
	query := callback.Query()
	query.Add("code", codeParam)

	if redirectParam != "" {
		query.Add("redirect", redirectParam)
	}

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
