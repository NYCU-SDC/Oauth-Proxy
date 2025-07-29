#!/bin/bash

echo "Starting OAuth Proxy Service..."
echo "Port: ${PORT:-8081}"
echo "OAuth Redirect URL: ${OAUTH_REDIRECT_URL}"

go run cmd/oauth-proxy/main.go
