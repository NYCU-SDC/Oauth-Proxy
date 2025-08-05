package config

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
)

var (
	ErrMissingToken = errors.New("TOKEN is required")
)

type Config struct {
	Token            string
	Port             string
	OAuthRedirectURL string
	Debug            bool
}

func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	config := &Config{
		Token:            os.Getenv("TOKEN"),
		Port:             getEnv("PORT", "8081"),
		OAuthRedirectURL: os.Getenv("OAUTH_REDIRECT_URL"),
		Debug:            getEnv("DEBUG", "false") == "true",
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.Token == "" {
		return ErrMissingToken
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
