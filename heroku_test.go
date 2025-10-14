package heroku_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dyno-proxy/plugins/heroku-oauth"
)

func TestNewWithConfig(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	cfg.Scopes = "identity"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	if handler == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestNewWithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("HEROKU_OAUTH_ID", "env-client-id")
	os.Setenv("HEROKU_OAUTH_SECRET", "env-client-secret")
	defer func() {
		os.Unsetenv("HEROKU_OAUTH_ID")
		os.Unsetenv("HEROKU_OAUTH_SECRET")
	}()

	cfg := heroku.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	if handler == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestNewWithoutClientID(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}

	if !strings.Contains(err.Error(), "client_id is required") {
		t.Errorf("expected error about missing client_id, got: %v", err)
	}
}

func TestNewWithoutClientSecret(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err == nil {
		t.Fatal("expected error for missing client_secret")
	}

	if !strings.Contains(err.Error(), "client_secret is required") {
		t.Errorf("expected error about missing client_secret, got: %v", err)
	}
}

func TestOAuthInitiation(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called during OAuth initiation")
	})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Should redirect to Heroku OAuth
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	// Parse the redirect URL
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	// Check that it's the correct Heroku OAuth URL
	if redirectURL.Host != "id.heroku.com" {
		t.Errorf("expected host id.heroku.com, got %s", redirectURL.Host)
	}

	if redirectURL.Path != "/oauth/authorize" {
		t.Errorf("expected path /oauth/authorize, got %s", redirectURL.Path)
	}

	// Check query parameters
	query := redirectURL.Query()
	if query.Get("client_id") != "test-client-id" {
		t.Errorf("expected client_id test-client-id, got %s", query.Get("client_id"))
	}

	if query.Get("response_type") != "code" {
		t.Errorf("expected response_type code, got %s", query.Get("response_type"))
	}

	if query.Get("scope") != "identity" {
		t.Errorf("expected scope identity, got %s", query.Get("scope"))
	}

	if query.Get("state") == "" {
		t.Error("expected state parameter")
	}

	// Check that state cookie is set
	cookies := recorder.Header()["Set-Cookie"]
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header")
	}

	stateCookieFound := false
	for _, cookie := range cookies {
		if strings.Contains(cookie, "heroku_oauth_state") {
			stateCookieFound = true
			break
		}
	}
	if !stateCookieFound {
		t.Error("expected heroku_oauth_state cookie")
	}
}

func TestAuthenticatedRequest(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("authenticated"))
	})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add authentication cookie
	req.AddCookie(&http.Cookie{
		Name:  "heroku_oauth_email",
		Value: "test@example.com",
	})

	handler.ServeHTTP(recorder, req)

	// Should call next handler
	if !nextCalled {
		t.Error("expected next handler to be called")
	}

	// Should add email header
	emailHeader := recorder.Header().Get("X-HEROKU-OAUTH")
	if emailHeader != "test@example.com" {
		t.Errorf("expected email header test@example.com, got %s", emailHeader)
	}
}

func TestOAuthCallbackSuccess(t *testing.T) {
	// Mock Heroku OAuth token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("expected path /oauth/token, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("expected method POST, got %s", r.Method)
		}

		// Return mock token response
		tokenResp := map[string]interface{}{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer tokenServer.Close()

	// Mock Heroku API account endpoint
	accountServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/account" {
			t.Errorf("expected path /account, got %s", r.URL.Path)
		}

		if r.Method != "GET" {
			t.Errorf("expected method GET, got %s", r.Method)
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer mock-access-token" {
			t.Errorf("expected Authorization header Bearer mock-access-token, got %s", authHeader)
		}

		// Return mock account response
		accountResp := map[string]interface{}{
			"email": "test@example.com",
			"id":    "user-123",
			"name":  "Test User",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(accountResp)
	}))
	defer accountServer.Close()

	// Create plugin with mocked endpoints
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", tokenServer.URL+"/oauth/token", accountServer.URL+"/account")
	if err != nil {
		t.Fatal(err)
	}

	// Create callback request
	state := "test-state"
	callbackURL := "http://localhost/auth/heroku/callback?code=test-code&state=" + state
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add encrypted state cookie
	req.AddCookie(createEncryptedStateCookie(t, state, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should redirect after successful authentication
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	// Should set email cookie
	cookies := recorder.Header()["Set-Cookie"]
	emailCookieFound := false
	for _, cookie := range cookies {
		if strings.Contains(cookie, "heroku_oauth_email") && strings.Contains(cookie, "test@example.com") {
			emailCookieFound = true
			break
		}
	}
	if !emailCookieFound {
		t.Error("expected heroku_oauth_email cookie with test@example.com")
	}
}

func TestOAuthCallbackWithError(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create callback request with error
	callbackURL := "http://localhost/auth/heroku/callback?error=access_denied&code=test-code&state=test-state"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should return error
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "OAuth error: access_denied") {
		t.Errorf("expected OAuth error message, got: %s", body)
	}
}

func TestOAuthCallbackWithInvalidState(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create callback request with invalid state
	callbackURL := "http://localhost/auth/heroku/callback?code=test-code&state=invalid-state"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Add different state cookie
	req.AddCookie(&http.Cookie{
		Name:  "heroku_oauth_state",
		Value: "different-state",
	})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should return error
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}

	body := recorder.Body.String()
	if !strings.Contains(body, "Invalid state cookie") {
		t.Errorf("expected invalid state error message, got: %s", body)
	}
}

func TestDefaultScopes(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	// Don't set scopes, should use default

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Should redirect to Heroku OAuth
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	query := redirectURL.Query()
	if query.Get("scope") != "identity" {
		t.Errorf("expected default scope identity, got %s", query.Get("scope"))
	}
}

func TestCustomScopes(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	cfg.Scopes = "identity,read"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

	// Should redirect to Heroku OAuth
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}

	query := redirectURL.Query()
	if query.Get("scope") != "identity,read" {
		t.Errorf("expected custom scope identity,read, got %s", query.Get("scope"))
	}
}

// Helper function to create an encrypted state cookie for testing
func createEncryptedStateCookie(t *testing.T, state, clientSecret string) *http.Cookie {
	encryptedState, err := heroku.EncryptState(state, clientSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt state: %v", err)
	}

	return &http.Cookie{
		Name:  "heroku_oauth_state",
		Value: encryptedState,
	}
}

// Helper function to create an encrypted token cookie for testing
func createEncryptedTokenCookie(t *testing.T, tokenData *heroku.TokenData, clientSecret string) *http.Cookie {
	encryptedToken, err := heroku.EncryptTokenData(tokenData, clientSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt token data: %v", err)
	}

	return &http.Cookie{
		Name:  "heroku_oauth_token",
		Value: encryptedToken,
	}
}

func TestTokenDataEncryptionDecryption(t *testing.T) {
	tokenData := &heroku.TokenData{
		AccessToken:  "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		TokenType:    "Bearer",
		ExpiresIn:    28799,
		RefreshToken: "01234567-89ab-cdef-0123-456789abcdef",
		UserID:       "01234567-89ab-cdef-0123-456789abcdef",
		SessionNonce: "2bf3ec81701ec291",
		Email:        "test@example.com",
		Teams:        "team1,team2",
		ExpiresAt:    1234567890,
	}

	clientSecret := "test-client-secret"

	encrypted, err := heroku.EncryptTokenData(tokenData, clientSecret)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := heroku.DecryptTokenData(encrypted, clientSecret)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify all fields match
	if decrypted.AccessToken != tokenData.AccessToken {
		t.Errorf("AccessToken mismatch: expected %s, got %s", tokenData.AccessToken, decrypted.AccessToken)
	}
	if decrypted.TokenType != tokenData.TokenType {
		t.Errorf("TokenType mismatch: expected %s, got %s", tokenData.TokenType, decrypted.TokenType)
	}
	if decrypted.ExpiresIn != tokenData.ExpiresIn {
		t.Errorf("ExpiresIn mismatch: expected %d, got %d", tokenData.ExpiresIn, decrypted.ExpiresIn)
	}
	if decrypted.RefreshToken != tokenData.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", tokenData.RefreshToken, decrypted.RefreshToken)
	}
	if decrypted.UserID != tokenData.UserID {
		t.Errorf("UserID mismatch: expected %s, got %s", tokenData.UserID, decrypted.UserID)
	}
	if decrypted.SessionNonce != tokenData.SessionNonce {
		t.Errorf("SessionNonce mismatch: expected %s, got %s", tokenData.SessionNonce, decrypted.SessionNonce)
	}
	if decrypted.Email != tokenData.Email {
		t.Errorf("Email mismatch: expected %s, got %s", tokenData.Email, decrypted.Email)
	}
	if decrypted.Teams != tokenData.Teams {
		t.Errorf("Teams mismatch: expected %s, got %s", tokenData.Teams, decrypted.Teams)
	}
	if decrypted.ExpiresAt != tokenData.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: expected %d, got %d", tokenData.ExpiresAt, decrypted.ExpiresAt)
	}
}

func TestAuthenticatedRequestWithEncryptedToken(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Verify headers are set correctly
		email := rw.Header().Get("X-HEROKU-OAUTH")
		teams := rw.Header().Get("X-DYNO-PROXY-HEROKU-TEAMS")

		if email != "test@example.com" {
			t.Errorf("expected email header test@example.com, got %s", email)
		}
		if teams != "team1,team2" {
			t.Errorf("expected teams header team1,team2, got %s", teams)
		}
	})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create token data
	tokenData := &heroku.TokenData{
		AccessToken:  "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "01234567-89ab-cdef-0123-456789abcdef",
		UserID:       "01234567-89ab-cdef-0123-456789abcdef",
		SessionNonce: "2bf3ec81701ec291",
		Email:        "test@example.com",
		Teams:        "team1,team2",
		ExpiresAt:    time.Now().Unix() + 3600, // 1 hour from now
	}

	// Create request with encrypted token cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedTokenCookie(t, tokenData, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should call next handler (not redirect)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestTokenRefreshSuccess(t *testing.T) {
	// Mock Heroku OAuth refresh endpoint
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("expected path /oauth/token, got %s", r.URL.Path)
		}

		if r.Method != "POST" {
			t.Errorf("expected method POST, got %s", r.Method)
		}

		// Check that the request contains refresh_token grant type
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("expected grant_type refresh_token, got %s", r.Form.Get("grant_type"))
		}

		// Return mock refreshed token response
		tokenResp := map[string]interface{}{
			"access_token":  "HRKU-new-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "new-refresh-token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResp)
	}))
	defer refreshServer.Close()

	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("refreshed"))
	})

	handler, err := heroku.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", refreshServer.URL+"/oauth/token", "https://api.heroku.com/account")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired token data with valid refresh token
	expiredTime := time.Now().Unix() - 3600                     // 1 hour ago
	refreshExpiresAt := time.Now().Unix() + (30 * 24 * 60 * 60) // 30 days from now

	tokenData := &heroku.TokenData{
		AccessToken:      "HRKU-expired-access-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "valid-refresh-token",
		UserID:           "user-123",
		SessionNonce:     "session-nonce",
		Email:            "test@example.com",
		Teams:            "team1,team2",
		ExpiresAt:        expiredTime,
		RefreshExpiresAt: refreshExpiresAt,
	}

	// Create request with expired token cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedTokenCookie(t, tokenData, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should call next handler after successful refresh
	if !nextCalled {
		t.Error("expected next handler to be called after token refresh")
	}

	if recorder.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}

	// Should set email header
	emailHeader := recorder.Header().Get("X-HEROKU-OAUTH")
	if emailHeader != "test@example.com" {
		t.Errorf("expected email header test@example.com, got %s", emailHeader)
	}

	// Should set teams header
	teamsHeader := recorder.Header().Get("X-DYNO-PROXY-HEROKU-TEAMS")
	if teamsHeader != "team1,team2" {
		t.Errorf("expected teams header team1,team2, got %s", teamsHeader)
	}

	// Should update the token cookie with new access token
	cookies := recorder.Header()["Set-Cookie"]
	tokenCookieUpdated := false
	for _, cookie := range cookies {
		if strings.Contains(cookie, "heroku_oauth_token") {
			tokenCookieUpdated = true
			break
		}
	}
	if !tokenCookieUpdated {
		t.Error("expected heroku_oauth_token cookie to be updated")
	}
}

func TestTokenRefreshFailure(t *testing.T) {
	// Mock Heroku OAuth refresh endpoint that returns error
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer refreshServer.Close()

	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when refresh fails")
	})

	handler, err := heroku.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", refreshServer.URL+"/oauth/token", "https://api.heroku.com/account")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired token data with valid refresh token
	expiredTime := time.Now().Unix() - 3600                     // 1 hour ago
	refreshExpiresAt := time.Now().Unix() + (30 * 24 * 60 * 60) // 30 days from now

	tokenData := &heroku.TokenData{
		AccessToken:      "HRKU-expired-access-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "invalid-refresh-token",
		UserID:           "user-123",
		SessionNonce:     "session-nonce",
		Email:            "test@example.com",
		Teams:            "team1,team2",
		ExpiresAt:        expiredTime,
		RefreshExpiresAt: refreshExpiresAt,
	}

	// Create request with expired token cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedTokenCookie(t, tokenData, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should redirect to OAuth when refresh fails
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header for OAuth redirect")
	}

	// Should clear authentication cookies
	cookies := recorder.Header()["Set-Cookie"]
	clearedCookies := 0
	for _, cookie := range cookies {
		if strings.Contains(cookie, "heroku_oauth_token") && (strings.Contains(cookie, "Max-Age=-1") || strings.Contains(cookie, "Max-Age=0")) {
			clearedCookies++
		}
		if strings.Contains(cookie, "heroku_oauth_email") && (strings.Contains(cookie, "Max-Age=-1") || strings.Contains(cookie, "Max-Age=0")) {
			clearedCookies++
		}
		if strings.Contains(cookie, "heroku_oauth_teams") && (strings.Contains(cookie, "Max-Age=-1") || strings.Contains(cookie, "Max-Age=0")) {
			clearedCookies++
		}
	}
	if clearedCookies == 0 {
		t.Errorf("expected authentication cookies to be cleared, got cookies: %v", cookies)
	}
}

func TestTokenRefreshWithExpiredRefreshToken(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when refresh token is expired")
	})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired token data with expired refresh token
	expiredTime := time.Now().Unix() - 3600        // 1 hour ago
	expiredRefreshTime := time.Now().Unix() - 3600 // 1 hour ago

	tokenData := &heroku.TokenData{
		AccessToken:      "HRKU-expired-access-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "expired-refresh-token",
		UserID:           "user-123",
		SessionNonce:     "session-nonce",
		Email:            "test@example.com",
		Teams:            "team1,team2",
		ExpiresAt:        expiredTime,
		RefreshExpiresAt: expiredRefreshTime,
	}

	// Create request with expired token cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedTokenCookie(t, tokenData, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should redirect to OAuth when refresh token is expired
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header for OAuth redirect")
	}
}

func TestTokenRefreshWithoutRefreshToken(t *testing.T) {
	cfg := heroku.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when no refresh token is available")
	})

	handler, err := heroku.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired token data without refresh token
	expiredTime := time.Now().Unix() - 3600 // 1 hour ago

	tokenData := &heroku.TokenData{
		AccessToken:      "HRKU-expired-access-token",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "", // No refresh token
		UserID:           "user-123",
		SessionNonce:     "session-nonce",
		Email:            "test@example.com",
		Teams:            "team1,team2",
		ExpiresAt:        expiredTime,
		RefreshExpiresAt: 0,
	}

	// Create request with expired token cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedTokenCookie(t, tokenData, "test-client-secret"))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Should redirect to OAuth when no refresh token is available
	if recorder.Code != http.StatusFound {
		t.Errorf("expected status %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header for OAuth redirect")
	}
}

func TestTokenDataWithRefreshExpiration(t *testing.T) {
	tokenData := &heroku.TokenData{
		AccessToken:      "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		TokenType:        "Bearer",
		ExpiresIn:        3600,
		RefreshToken:     "01234567-89ab-cdef-0123-456789abcdef",
		UserID:           "01234567-89ab-cdef-0123-456789abcdef",
		SessionNonce:     "2bf3ec81701ec291",
		Email:            "test@example.com",
		Teams:            "team1,team2",
		ExpiresAt:        1234567890,
		RefreshExpiresAt: 1234567890 + (30 * 24 * 60 * 60), // 30 days later
	}

	clientSecret := "test-client-secret"

	encrypted, err := heroku.EncryptTokenData(tokenData, clientSecret)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := heroku.DecryptTokenData(encrypted, clientSecret)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify all fields match including new refresh expiration field
	if decrypted.AccessToken != tokenData.AccessToken {
		t.Errorf("AccessToken mismatch: expected %s, got %s", tokenData.AccessToken, decrypted.AccessToken)
	}
	if decrypted.TokenType != tokenData.TokenType {
		t.Errorf("TokenType mismatch: expected %s, got %s", tokenData.TokenType, decrypted.TokenType)
	}
	if decrypted.ExpiresIn != tokenData.ExpiresIn {
		t.Errorf("ExpiresIn mismatch: expected %d, got %d", tokenData.ExpiresIn, decrypted.ExpiresIn)
	}
	if decrypted.RefreshToken != tokenData.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", tokenData.RefreshToken, decrypted.RefreshToken)
	}
	if decrypted.UserID != tokenData.UserID {
		t.Errorf("UserID mismatch: expected %s, got %s", tokenData.UserID, decrypted.UserID)
	}
	if decrypted.SessionNonce != tokenData.SessionNonce {
		t.Errorf("SessionNonce mismatch: expected %s, got %s", tokenData.SessionNonce, decrypted.SessionNonce)
	}
	if decrypted.Email != tokenData.Email {
		t.Errorf("Email mismatch: expected %s, got %s", tokenData.Email, decrypted.Email)
	}
	if decrypted.Teams != tokenData.Teams {
		t.Errorf("Teams mismatch: expected %s, got %s", tokenData.Teams, decrypted.Teams)
	}
	if decrypted.ExpiresAt != tokenData.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: expected %d, got %d", tokenData.ExpiresAt, decrypted.ExpiresAt)
	}
	if decrypted.RefreshExpiresAt != tokenData.RefreshExpiresAt {
		t.Errorf("RefreshExpiresAt mismatch: expected %d, got %d", tokenData.RefreshExpiresAt, decrypted.RefreshExpiresAt)
	}
}
