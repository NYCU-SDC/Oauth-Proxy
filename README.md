# OAuth Proxy

This is a simple Go server that acts as a reverse proxy for OAuth callbacks.

## Running the server

To run the server, you need to have Go installed. You can then run the following command in the root of the project:

```bash
go run .
```

This will start the server on port 8080.

## How it works

The server has a single endpoint, `/auth/google/callback`, which is the callback URL for the Google OAuth flow.

When a user is redirected to this endpoint, the server extracts the `state` and `code` from the query parameters.

The `state` parameter is expected to be the URL of the main backend server. The server then redirects the user to this URL, including the `code` and `state` in the query parameters.

This allows the main backend server to handle the OAuth callback, while the proxy server handles the unique URL for each snapshot.
