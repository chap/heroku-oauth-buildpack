// Package heroku implements Heroku OAuth middleware for dyno-proxy.
package heroku

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// Heroku OAuth endpoints
	herokuOAuthAuthorizeURL = "https://id.heroku.com/oauth/authorize"
	herokuOAuthTokenURL     = "https://id.heroku.com/oauth/token"
	herokuOAuthRefreshURL   = "https://id.heroku.com/oauth/token"
	herokuAPIAccountURL     = "https://api.heroku.com/account"

	// Default scopes
	defaultScopes = "identity"

	// Session keys
	sessionStateKey       = "heroku_oauth_state"
	sessionEmailKey       = "heroku_oauth_email"
	sessionOriginalURLKey = "heroku_oauth_original_url"
	sessionTeamsKey       = "heroku_oauth_teams"
	sessionTokenKey       = "heroku_oauth_token"
)

// Log level constants
const (
	LogLevelOff   = 0
	LogLevelError = 1
	LogLevelWarn  = 2
	LogLevelInfo  = 3
	LogLevelDebug = 4
)

// getLogLevel returns the current log level based on environment variables
func getLogLevel() int {
	// Check HEROKU_OAUTH_LOG_LEVEL first
	if level := parseLogLevel(os.Getenv("HEROKU_OAUTH_LOG_LEVEL")); level >= 0 {
		return level
	}

	// Fall back to DYNO_PROXY_LOG_LEVEL
	if level := parseLogLevel(os.Getenv("DYNO_PROXY_LOG_LEVEL")); level >= 0 {
		return level
	}

	// Default to WARN level
	return LogLevelWarn
}

// parseLogLevel parses a log level string or integer, case-insensitive
func parseLogLevel(levelStr string) int {
	if levelStr == "" {
		return -1
	}

	// Try parsing as integer first
	if level, err := strconv.Atoi(levelStr); err == nil {
		if level >= LogLevelOff && level <= LogLevelDebug {
			return level
		}
		return -1
	}

	// Parse as string (case-insensitive)
	levelStr = strings.ToUpper(strings.TrimSpace(levelStr))
	switch levelStr {
	case "OFF", "0":
		return LogLevelOff
	case "ERROR", "1":
		return LogLevelError
	case "WARN", "WARNING", "2":
		return LogLevelWarn
	case "INFO", "3":
		return LogLevelInfo
	case "DEBUG", "4":
		return LogLevelDebug
	default:
		return -1
	}
}

// logInfo logs a message if log level is INFO or higher
func logInfo(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelInfo {
		log.Printf(format, args...)
	}
}

// logTraefikStyle logs in Traefik-style format: timestamp level message
func logTraefikStyle(level, message string) {
	if getLogLevel() >= LogLevelInfo {
		timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
		log.Printf("%s %s %s", timestamp, level, message)
	}
}

// logWarn logs a warning message if log level is WARN or higher
func logWarn(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelWarn {
		timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
		log.Printf("%s WARN %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// logError logs an error message if log level is ERROR or higher
func logError(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelError {
		timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
		log.Printf("%s ERROR %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// logDebug logs a debug message if log level is DEBUG
func logDebug(format string, args ...interface{}) {
	if getLogLevel() >= LogLevelDebug {
		timestamp := time.Now().Format("2006-01-02T15:04:05.000Z")
		log.Printf("%s DEBUG %s", timestamp, fmt.Sprintf(format, args...))
	}
}

// Config the plugin configuration.
type Config struct {
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       string   `json:"scopes,omitempty"`
	CallbackPath string   `json:"callback_path,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	Domains      []string `json:"domains,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Scopes: defaultScopes,
	}
}

// HerokuOAuth implements the Heroku OAuth middleware.
type HerokuOAuth struct {
	next         http.Handler
	clientID     string
	clientSecret string
	scopes       string
	callbackPath string
	name         string
	domain       string
	domains      []string
	// For testing - allow overriding endpoints
	oauthTokenURL   string
	oauthRefreshURL string
	apiAccountURL   string
}

// New creates a new Heroku OAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Get client ID from config or environment
	clientID := config.ClientID
	if clientID == "" {
		clientID = os.Getenv("HEROKU_OAUTH_ID")
	}
	if clientID == "" {
		logError("CONFIG_ERROR error=missing_client_id message=client_id is required (set via config or HEROKU_OAUTH_ID environment variable)")
		return nil, fmt.Errorf("client_id is required (set via config or HEROKU_OAUTH_ID environment variable)")
	}

	// Get client secret from config or environment
	clientSecret := config.ClientSecret
	if clientSecret == "" {
		clientSecret = os.Getenv("HEROKU_OAUTH_SECRET")
	}
	if clientSecret == "" {
		logError("CONFIG_ERROR error=missing_client_secret message=client_secret is required (set via config or HEROKU_OAUTH_SECRET environment variable)")
		return nil, fmt.Errorf("client_secret is required (set via config or HEROKU_OAUTH_SECRET environment variable)")
	}

	// Use scopes from config or default
	scopes := config.Scopes
	if scopes == "" {
		scopes = defaultScopes
	}

	return &HerokuOAuth{
		next:            next,
		clientID:        clientID,
		clientSecret:    clientSecret,
		scopes:          scopes,
		callbackPath:    config.CallbackPath,
		name:            name,
		domain:          config.Domain,
		domains:         config.Domains,
		oauthTokenURL:   herokuOAuthTokenURL,
		oauthRefreshURL: herokuOAuthRefreshURL,
		apiAccountURL:   herokuAPIAccountURL,
	}, nil
}

// OAuthTokenResponse represents the response from Heroku's token endpoint.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id,omitempty"`
	SessionNonce string `json:"session_nonce,omitempty"`
}

// TokenData represents the complete token information stored in the cookie.
type TokenData struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	UserID           string `json:"user_id,omitempty"`
	SessionNonce     string `json:"session_nonce,omitempty"`
	Email            string `json:"email"`
	Teams            string `json:"teams,omitempty"`
	ExpiresAt        int64  `json:"expires_at"`         // Unix timestamp when access token expires
	RefreshExpiresAt int64  `json:"refresh_expires_at"` // Unix timestamp when refresh token expires
}

// HerokuAccount represents the user's Heroku account information.
type HerokuAccount struct {
	Email string `json:"email"`
	ID    string `json:"id"`
	Name  string `json:"name"`
}

// HerokuOrganization represents a Heroku organization/team.
type HerokuOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (h *HerokuOAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check for logout parameter
	if req.URL.Query().Get("heroku-oauth-logout") == "true" {
		h.handleLogout(rw, req)
		return
	}

	// Check if this is an OAuth callback by looking for code and state parameters
	// If callbackPath is configured, also check the path
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	isCallback := code != "" && state != ""
	if h.callbackPath != "" {
		isCallback = isCallback && req.URL.Path == h.callbackPath
	}

	if isCallback {
		h.handleOAuthCallback(rw, req)
		return
	}

	// Check if user is already authenticated
	if tokenData := h.getAuthenticatedTokenData(req); tokenData != nil {
		// Log token check
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logTraefikStyle("INFO", fmt.Sprintf("TOKEN_CHECK user_email=%s user_id=%s request_id=%s url=%s",
			tokenData.Email, tokenData.UserID, requestID, req.URL.String()))

		// Check if token is expired
		if time.Now().Unix() > tokenData.ExpiresAt {
			// Token expired, try to refresh if refresh token is available and not expired
			if tokenData.RefreshToken != "" && time.Now().Unix() < tokenData.RefreshExpiresAt {
				// Attempt to refresh the token
				newTokenResp, err := h.refreshAccessToken(tokenData.RefreshToken)
				if err == nil {
					// Refresh successful, update token data
					updatedTokenData := &TokenData{
						AccessToken:      newTokenResp.AccessToken,
						TokenType:        newTokenResp.TokenType,
						ExpiresIn:        newTokenResp.ExpiresIn,
						RefreshToken:     newTokenResp.RefreshToken, // Use new refresh token if provided
						UserID:           tokenData.UserID,
						SessionNonce:     tokenData.SessionNonce,
						Email:            tokenData.Email,
						Teams:            tokenData.Teams,
						ExpiresAt:        time.Now().Unix() + int64(newTokenResp.ExpiresIn),
						RefreshExpiresAt: tokenData.RefreshExpiresAt, // Keep existing refresh expiration
					}

					// If new refresh token is provided, update the expiration
					if newTokenResp.RefreshToken != "" {
						updatedTokenData.RefreshExpiresAt = time.Now().Unix() + (30 * 24 * 60 * 60) // 30 days
					}

					// Encrypt and store the updated token data
					encryptedToken, err := EncryptTokenData(updatedTokenData, h.clientSecret)
					if err == nil {
						http.SetCookie(rw, &http.Cookie{
							Name:     sessionTokenKey,
							Value:    encryptedToken,
							Path:     "/",
							HttpOnly: true,
							Secure:   req.TLS != nil,
							SameSite: http.SameSiteLaxMode,
						})

						// Update tokenData for header injection
						tokenData = updatedTokenData
					}
				} else {
					// Log refresh token failure
					requestID := req.Header.Get("X-Request-ID")
					if requestID == "" {
						requestID = "unknown"
					}
					logWarn("REFRESH_FAILURE error=refresh_token_failed error_detail=%v user_email=%s user_id=%s request_id=%s url=%s",
						err, tokenData.Email, tokenData.UserID, requestID, req.URL.String())
				}
			}

			// If refresh failed or no refresh token available, clear cookies and redirect to OAuth
			if time.Now().Unix() > tokenData.ExpiresAt {
				requestID := req.Header.Get("X-Request-ID")
				if requestID == "" {
					requestID = "unknown"
				}
				logWarn("REFRESH_FAILURE user_email=%s user_id=%s request_id=%s url=%s",
					tokenData.Email, tokenData.UserID, requestID, req.URL.String())
				h.clearAuthenticationCookies(rw, req)
				h.initiateOAuth(rw, req)
				return
			}
		}

		// User is authenticated, add headers and continue
		rw.Header().Set("X-DYNO-PROXY-HEROKU-EMAIL", tokenData.Email)

		if tokenData.Teams != "" {
			rw.Header().Set("X-DYNO-PROXY-HEROKU-TEAMS", tokenData.Teams)
		}

		h.next.ServeHTTP(rw, req)
		return
	}

	// User is not authenticated, redirect to OAuth
	h.initiateOAuth(rw, req)
}

// initiateOAuth redirects the user to Heroku's OAuth authorization page.
func (h *HerokuOAuth) initiateOAuth(rw http.ResponseWriter, req *http.Request) {
	// Generate a cryptographically secure random state parameter
	state, err := GenerateSecureState()
	if err != nil {
		http.Error(rw, "Failed to generate secure state", http.StatusInternalServerError)
		return
	}

	// Encrypt the state using the client secret
	encryptedState, err := EncryptState(state, h.clientSecret)
	if err != nil {
		http.Error(rw, "Failed to encrypt state", http.StatusInternalServerError)
		return
	}

	// Store encrypted state in a secure cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionStateKey,
		Value:    encryptedState,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Store the original URL for redirect after authentication
	originalURL := req.URL.String()
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionOriginalURLKey,
		Value:    originalURL,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Build authorization URL
	authURL, _ := url.Parse(herokuOAuthAuthorizeURL)
	params := authURL.Query()
	params.Set("client_id", h.clientID)
	params.Set("response_type", "code")
	params.Set("scope", h.scopes)
	params.Set("state", state)
	authURL.RawQuery = params.Encode()

	// Redirect to Heroku OAuth
	http.Redirect(rw, req, authURL.String(), http.StatusFound)
}

// handleOAuthCallback handles the OAuth callback from Heroku.
func (h *HerokuOAuth) handleOAuthCallback(rw http.ResponseWriter, req *http.Request) {
	// Get the authorization code and state from query parameters
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")
	errorParam := req.URL.Query().Get("error")

	// Check for OAuth errors
	if errorParam != "" {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE oauth_error=%s request_id=%s url=%s", errorParam, requestID, req.URL.String())
		http.Error(rw, fmt.Sprintf("OAuth error: %s", errorParam), http.StatusBadRequest)
		return
	}

	// Validate state parameter
	if state == "" {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=missing_state_parameter request_id=%s url=%s", requestID, req.URL.String())
		http.Error(rw, "Missing state parameter", http.StatusBadRequest)
		return
	}

	// Get stored encrypted state from cookie
	cookie, err := req.Cookie(sessionStateKey)
	if err != nil {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=missing_state_cookie request_id=%s url=%s", requestID, req.URL.String())
		http.Error(rw, "Missing state cookie", http.StatusBadRequest)
		return
	}

	// Decrypt the stored state using the client secret
	decryptedState, err := DecryptState(cookie.Value, h.clientSecret)
	if err != nil {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=invalid_state_cookie request_id=%s url=%s", requestID, req.URL.String())
		http.Error(rw, "Invalid state cookie", http.StatusBadRequest)
		return
	}

	// Validate that the decrypted state matches the callback state
	if decryptedState != state {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=state_mismatch request_id=%s url=%s", requestID, req.URL.String())
		http.Error(rw, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for access token
	tokenResp, err := h.exchangeCodeForToken(code)
	if err != nil {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=token_exchange_failed error_detail=%v request_id=%s url=%s", err, requestID, req.URL.String())
		http.Error(rw, fmt.Sprintf("Failed to exchange code for token: %v", err), http.StatusInternalServerError)
		return
	}

	// Get user information from Heroku API
	account, err := h.getUserInfo(tokenResp.AccessToken)
	if err != nil {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=get_user_info_failed error_detail=%v request_id=%s url=%s", err, requestID, req.URL.String())
		http.Error(rw, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Get user organizations/teams from Heroku API
	organizations, err := h.getUserOrganizations(tokenResp.AccessToken)
	if err != nil {
		// Log error but don't fail the OAuth flow if teams info is unavailable
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_WARNING error=get_user_organizations_failed error_detail=%v request_id=%s url=%s", err, requestID, req.URL.String())
		organizations = []HerokuOrganization{}
	}

	// Validate user's email domain if domain restrictions are configured
	if err := h.validateEmailDomain(account.Email); err != nil {
		requestID := req.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "unknown"
		}
		logWarn("AUTH_FAILURE error=domain_validation_failed user_email=%s error_detail=%v request_id=%s url=%s",
			account.Email, err, requestID, req.URL.String())
		h.renderDomainError(rw, err)
		return
	}

	// Create token data with all information
	var teamNames []string
	for _, org := range organizations {
		teamNames = append(teamNames, org.Name)
	}
	teamsValue := strings.Join(teamNames, ",")

	// Calculate refresh token expiration (typically 30 days from now)
	refreshExpiresAt := time.Now().Unix() + (30 * 24 * 60 * 60) // 30 days in seconds

	tokenData := &TokenData{
		AccessToken:      tokenResp.AccessToken,
		TokenType:        tokenResp.TokenType,
		ExpiresIn:        tokenResp.ExpiresIn,
		RefreshToken:     tokenResp.RefreshToken,
		UserID:           tokenResp.UserID,
		SessionNonce:     tokenResp.SessionNonce,
		Email:            account.Email,
		Teams:            teamsValue,
		ExpiresAt:        time.Now().Unix() + int64(tokenResp.ExpiresIn),
		RefreshExpiresAt: refreshExpiresAt,
	}

	// Encrypt and store the complete token data
	encryptedToken, err := EncryptTokenData(tokenData, h.clientSecret)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Failed to encrypt token data: %v", err), http.StatusInternalServerError)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     sessionTokenKey,
		Value:    encryptedToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Store user email in cookie for backward compatibility
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionEmailKey,
		Value:    account.Email,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Store teams information in cookie for backward compatibility
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionTeamsKey,
		Value:    teamsValue,
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	// Clear the state cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionStateKey,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Redirect back to the original request or root
	redirectURL := req.URL.Query().Get("redirect_uri")
	if redirectURL == "" {
		// Try to get the original URL from cookie
		if originalURLCookie, err := req.Cookie(sessionOriginalURLKey); err == nil {
			redirectURL = originalURLCookie.Value
		}
	}
	if redirectURL == "" {
		redirectURL = "/"
	}

	// Clear the original URL cookie
	http.SetCookie(rw, &http.Cookie{
		Name:     sessionOriginalURLKey,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Log successful login
	requestID := req.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = "unknown"
	}
	logTraefikStyle("INFO", fmt.Sprintf("LOGIN user_email=%s user_id=%s request_id=%s url=%s",
		account.Email, account.ID, requestID, req.URL.String()))

	http.Redirect(rw, req, redirectURL, http.StatusFound)
}

// exchangeCodeForToken exchanges the authorization code for an access token.
func (h *HerokuOAuth) exchangeCodeForToken(code string) (*OAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_secret", h.clientSecret)
	data.Set("client_id", h.clientID)

	req, err := http.NewRequest("POST", h.oauthTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			logError("API_ERROR error=token_exchange_5xx status_code=%d message=Heroku OAuth token exchange returned 5xx error", resp.StatusCode)
		}
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// refreshAccessToken exchanges a refresh token for a new access token.
func (h *HerokuOAuth) refreshAccessToken(refreshToken string) (*OAuthTokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_secret", h.clientSecret)
	data.Set("client_id", h.clientID)

	req, err := http.NewRequest("POST", h.oauthRefreshURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			logError("API_ERROR error=token_refresh_5xx status_code=%d message=Heroku OAuth token refresh returned 5xx error", resp.StatusCode)
		}
		return nil, fmt.Errorf("token refresh failed with status %d", resp.StatusCode)
	}

	var tokenResp OAuthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getUserInfo fetches user information from the Heroku API.
func (h *HerokuOAuth) getUserInfo(accessToken string) (*HerokuAccount, error) {
	req, err := http.NewRequest("GET", h.apiAccountURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			logError("API_ERROR error=get_user_info_5xx status_code=%d message=Heroku API get user info returned 5xx error", resp.StatusCode)
		}
		return nil, fmt.Errorf("failed to get user info with status %d", resp.StatusCode)
	}

	var account HerokuAccount
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, err
	}

	return &account, nil
}

// getUserOrganizations fetches the user's organization memberships from the Heroku API.
func (h *HerokuOAuth) getUserOrganizations(accessToken string) ([]HerokuOrganization, error) {
	req, err := http.NewRequest("GET", "https://api.heroku.com/organizations", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 {
			logError("API_ERROR error=get_user_organizations_5xx status_code=%d message=Heroku API get user organizations returned 5xx error", resp.StatusCode)
		}
		// If organizations endpoint fails, return empty slice rather than error
		// This allows the OAuth flow to continue even if teams info is unavailable
		return []HerokuOrganization{}, nil
	}

	var organizations []HerokuOrganization
	if err := json.NewDecoder(resp.Body).Decode(&organizations); err != nil {
		return nil, err
	}

	return organizations, nil
}

// getAuthenticatedTokenData retrieves and decrypts the authenticated user's token data from the session.
func (h *HerokuOAuth) getAuthenticatedTokenData(req *http.Request) *TokenData {
	cookie, err := req.Cookie(sessionTokenKey)
	if err != nil {
		// Fallback to old email-based authentication for backward compatibility
		if email := h.getAuthenticatedEmail(req); email != "" {
			// Return a minimal token data structure for backward compatibility
			return &TokenData{
				Email:     email,
				Teams:     h.getAuthenticatedTeamsString(req),
				ExpiresAt: time.Now().Unix() + 3600, // Default 1 hour expiration
			}
		}
		return nil
	}

	tokenData, err := DecryptTokenData(cookie.Value, h.clientSecret)
	if err != nil {
		// If decryption fails, fallback to old email-based authentication
		if email := h.getAuthenticatedEmail(req); email != "" {
			return &TokenData{
				Email:     email,
				Teams:     h.getAuthenticatedTeamsString(req),
				ExpiresAt: time.Now().Unix() + 3600, // Default 1 hour expiration
			}
		}
		return nil
	}

	return tokenData
}

// getAuthenticatedEmail retrieves the authenticated user's email from the session (backward compatibility).
func (h *HerokuOAuth) getAuthenticatedEmail(req *http.Request) string {
	cookie, err := req.Cookie(sessionEmailKey)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// getAuthenticatedTeams retrieves the authenticated user's teams from the session.
func (h *HerokuOAuth) getAuthenticatedTeams(req *http.Request) []HerokuOrganization {
	cookie, err := req.Cookie(sessionTeamsKey)
	if err != nil {
		return []HerokuOrganization{}
	}

	// Parse comma-separated team names
	teamNames := strings.Split(cookie.Value, ",")
	var organizations []HerokuOrganization
	for _, name := range teamNames {
		if strings.TrimSpace(name) != "" {
			organizations = append(organizations, HerokuOrganization{
				Name: strings.TrimSpace(name),
			})
		}
	}

	return organizations
}

// getAuthenticatedTeamsString retrieves the authenticated user's teams as a comma-separated string.
func (h *HerokuOAuth) getAuthenticatedTeamsString(req *http.Request) string {
	cookie, err := req.Cookie(sessionTeamsKey)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// clearAuthenticationCookies clears all authentication-related cookies.
func (h *HerokuOAuth) clearAuthenticationCookies(rw http.ResponseWriter, req *http.Request) {
	cookies := []string{sessionTokenKey, sessionEmailKey, sessionTeamsKey, sessionStateKey, sessionOriginalURLKey}

	for _, cookieName := range cookies {
		http.SetCookie(rw, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   req.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

// handleLogout handles the logout request by deleting the authentication cookies.
func (h *HerokuOAuth) handleLogout(rw http.ResponseWriter, req *http.Request) {
	// Get user info before clearing cookies for logging
	var userEmail, userID string
	if tokenData := h.getAuthenticatedTokenData(req); tokenData != nil {
		userEmail = tokenData.Email
		userID = tokenData.UserID
	}

	// Clear all authentication cookies
	h.clearAuthenticationCookies(rw, req)

	// Log logout event
	requestID := req.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = "unknown"
	}
	if userEmail != "" {
		logTraefikStyle("INFO", fmt.Sprintf("LOGOUT user_email=%s user_id=%s request_id=%s url=%s",
			userEmail, userID, requestID, req.URL.String()))
	} else {
		logTraefikStyle("INFO", fmt.Sprintf("LOGOUT user_email=unknown user_id=unknown request_id=%s url=%s",
			requestID, req.URL.String()))
	}

	// Redirect back to the original request or root
	redirectURL := req.URL.Query().Get("redirect_uri")
	if redirectURL == "" {
		redirectURL = "/"
	}
	http.Redirect(rw, req, redirectURL, http.StatusFound)
}

// GenerateSecureState generates a cryptographically secure random state value.
func GenerateSecureState() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Encode as base64 for URL safety
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// EncryptState encrypts the state value using the client secret as the key.
func EncryptState(state, clientSecret string) (string, error) {
	// Create a hash of the client secret for the encryption key
	hash := sha256.Sum256([]byte(clientSecret))
	key := hash[:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the state
	ciphertext := gcm.Seal(nonce, nonce, []byte(state), nil)

	// Encode as base64 for URL safety
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptState decrypts the encrypted state using the client secret as the key.
func DecryptState(encryptedState, clientSecret string) (string, error) {
	// Decode from base64
	ciphertext, err := base64.URLEncoding.DecodeString(encryptedState)
	if err != nil {
		return "", err
	}

	// Create a hash of the client secret for the decryption key
	hash := sha256.Sum256([]byte(clientSecret))
	key := hash[:]

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Extract nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the state
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// EncryptTokenData encrypts the token data using the client secret as the key.
func EncryptTokenData(tokenData *TokenData, clientSecret string) (string, error) {
	// Serialize token data to JSON
	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token data: %v", err)
	}

	// Encrypt the JSON data
	return EncryptState(string(jsonData), clientSecret)
}

// DecryptTokenData decrypts the encrypted token data using the client secret as the key.
func DecryptTokenData(encryptedData, clientSecret string) (*TokenData, error) {
	// Decrypt the data
	decryptedData, err := DecryptState(encryptedData, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt token data: %v", err)
	}

	// Deserialize JSON data
	var tokenData TokenData
	if err := json.Unmarshal([]byte(decryptedData), &tokenData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token data: %v", err)
	}

	return &tokenData, nil
}

// validateEmailDomain checks if the user's email domain is allowed based on configuration.
func (h *HerokuOAuth) validateEmailDomain(email string) error {
	// Get allowed domains from configuration
	allowedDomains := h.getAllowedDomains()
	if len(allowedDomains) == 0 {
		// No domain restrictions configured
		return nil
	}

	// Extract domain from email
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format")
	}
	userDomain := strings.ToLower(parts[1])

	// Check if user's domain is in the allowed list
	for _, allowedDomain := range allowedDomains {
		if strings.ToLower(allowedDomain) == userDomain {
			return nil
		}
	}

	// Domain not allowed
	return &DomainValidationError{
		UserDomain:     userDomain,
		AllowedDomains: allowedDomains,
	}
}

// getAllowedDomains returns the list of allowed domains from configuration.
func (h *HerokuOAuth) getAllowedDomains() []string {
	var domains []string

	// Add single domain if configured
	if h.domain != "" {
		domains = append(domains, h.domain)
	}

	// Add multiple domains if configured
	domains = append(domains, h.domains...)

	return domains
}

// DomainValidationError represents a domain validation error.
type DomainValidationError struct {
	UserDomain     string
	AllowedDomains []string
}

func (e *DomainValidationError) Error() string {
	return fmt.Sprintf("email domain '%s' is not allowed", e.UserDomain)
}

// renderDomainError renders an HTML error page for domain validation failures.
func (h *HerokuOAuth) renderDomainError(rw http.ResponseWriter, err error) {
	domainErr, ok := err.(*DomainValidationError)
	if !ok {
		http.Error(rw, "Domain validation error", http.StatusForbidden)
		return
	}

	// Create a comma-separated list of allowed domains
	allowedDomainsStr := strings.Join(domainErr.AllowedDomains, ", ")

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied - Domain Restriction</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
            color: #333;
        }
        .error-container {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 30px;
            text-align: center;
        }
        .error-title {
            color: #dc3545;
            font-size: 24px;
            margin-bottom: 20px;
        }
        .error-message {
            font-size: 16px;
            margin-bottom: 20px;
        }
        .domain-info {
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .allowed-domains {
            font-weight: bold;
            color: #28a745;
        }
        .user-domain {
            font-weight: bold;
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1 class="error-title">Access Denied</h1>
        <p class="error-message">
            Your email address domain is not authorized to access this application.
        </p>
        <div class="domain-info">
            <p>Your email domain: <span class="user-domain">%s</span></p>
            <p>Allowed domains: <span class="allowed-domains">%s</span></p>
        </div>
        <p>
            Please contact your administrator if you believe this is an error, 
            or use an email address from one of the allowed domains.
        </p>
    </div>
</body>
</html>`, domainErr.UserDomain, allowedDomainsStr)

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte(html))
}

// NewForTesting creates a new Heroku OAuth plugin with custom endpoints for testing.
func NewForTesting(ctx context.Context, next http.Handler, config *Config, name string, oauthTokenURL, apiAccountURL string) (http.Handler, error) {
	// Get client ID from config or environment
	clientID := config.ClientID
	if clientID == "" {
		clientID = os.Getenv("HEROKU_OAUTH_ID")
	}
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required (set via config or HEROKU_OAUTH_ID environment variable)")
	}

	// Get client secret from config or environment
	clientSecret := config.ClientSecret
	if clientSecret == "" {
		clientSecret = os.Getenv("HEROKU_OAUTH_SECRET")
	}
	if clientSecret == "" {
		logError("CONFIG_ERROR error=missing_client_secret message=client_secret is required (set via config or HEROKU_OAUTH_SECRET environment variable)")
		return nil, fmt.Errorf("client_secret is required (set via config or HEROKU_OAUTH_SECRET environment variable)")
	}

	// Use scopes from config or default
	scopes := config.Scopes
	if scopes == "" {
		scopes = defaultScopes
	}

	return &HerokuOAuth{
		next:            next,
		clientID:        clientID,
		clientSecret:    clientSecret,
		scopes:          scopes,
		callbackPath:    config.CallbackPath,
		name:            name,
		domain:          config.Domain,
		domains:         config.Domains,
		oauthTokenURL:   oauthTokenURL,
		oauthRefreshURL: oauthTokenURL, // Use same URL for refresh in testing
		apiAccountURL:   apiAccountURL,
	}, nil
}
