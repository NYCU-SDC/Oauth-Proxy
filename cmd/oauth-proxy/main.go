package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oauth-proxy/internal/config"
	"oauth-proxy/internal/handler"
	"oauth-proxy/internal/oauth"
)

func main() {
	// Setup logger
	logger := log.New(os.Stdout, "[oauth-proxy] ", log.LstdFlags|log.Lshortfile)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("Failed to load configuration: %v", err)
	}

	logger.Printf("OAuth Proxy starting on port %s", cfg.Port)
	logger.Printf("Redirect URL: %s", cfg.OAuthRedirectURL)

	// Initialize OAuth service
	oauthService := oauth.NewService(
		cfg.GoogleOAuthClientID,
		cfg.GoogleOAuthSecret,
		cfg.OAuthRedirectURL,
	)

	// Initialize handlers
	h := handler.New(oauthService, logger)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /debug", h.DebugCallback)
	mux.HandleFunc("GET /auth/google/callback", h.HandleCallback)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Printf("Starting server on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Println("Shutting down server...")

	// Give outstanding requests a deadline for completion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Failed to shutdown server: %v", err)
	}

	logger.Println("Server gracefully stopped")
}
