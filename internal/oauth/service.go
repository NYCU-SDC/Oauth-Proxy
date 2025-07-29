package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Service struct {
	config *oauth2.Config
}

type TokenData struct {
	AccessToken  string                 `json:"access_token"`
	RefreshToken string                 `json:"refresh_token"`
	IDToken      string                 `json:"id_token"`
	TokenType    string                 `json:"token_type"`
	Expiry       interface{}            `json:"expiry"`
	UserInfo     map[string]interface{} `json:"user_info"`
}

func NewService(clientID, clientSecret, redirectURL string) *Service {
	return &Service{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"openid",
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (s *Service) ExchangeCodeForToken(ctx context.Context, code string) (*TokenData, error) {
	// Validate code parameter
	if code == "" {
		return nil, fmt.Errorf("authorization code is empty or missing")
	}

	// Exchange authorization code for token
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from Google
	userInfo, err := s.getUserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Extract ID token
	idToken := ""
	if idTokenInterface := token.Extra("id_token"); idTokenInterface != nil {
		if idTokenStr, ok := idTokenInterface.(string); ok {
			idToken = idTokenStr
		}
	}

	return &TokenData{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      idToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
		UserInfo:     userInfo,
	}, nil
}

func (s *Service) getUserInfo(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := s.config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get user info, status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
