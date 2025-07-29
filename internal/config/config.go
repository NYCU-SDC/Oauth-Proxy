package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

var (
	ErrMissingClientID     = errors.New("GOOGLE_OAUTH_CLIENT_ID is required")
	ErrMissingClientSecret = errors.New("GOOGLE_OAUTH_CLIENT_SECRET is required")
	ErrMissingRedirectURL  = errors.New("OAUTH_REDIRECT_URL is required")
)

type Config struct {
	Port                 string
	GoogleOAuthClientID  string
	GoogleOAuthSecret    string
	OAuthRedirectURL     string
	Debug                bool
}

func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	config := &Config{
		Port:                 getEnv("PORT", "8081"),
		GoogleOAuthClientID:  os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		GoogleOAuthSecret:    os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		OAuthRedirectURL:     os.Getenv("OAUTH_REDIRECT_URL"),
		Debug:                getEnv("DEBUG", "false") == "true",
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.GoogleOAuthClientID == "" {
		return ErrMissingClientID
	}
	if c.GoogleOAuthSecret == "" {
		return ErrMissingClientSecret
	}
	if c.OAuthRedirectURL == "" {
		return ErrMissingRedirectURL
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
