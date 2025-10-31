package heroku_oauth_buildpack_test

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

	heroku_oauth_buildpack "github.com/chap/heroku-oauth-buildpack"
)

func TestNewWithConfig(t *testing.T) {
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	cfg.Scopes = "identity"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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

	cfg := heroku_oauth_buildpack.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	if handler == nil {
		t.Fatal("handler should not be nil")
	}
}

func TestNewWithoutClientID(t *testing.T) {
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}

	if !strings.Contains(err.Error(), "client_id is required") {
		t.Errorf("expected error about missing client_id, got: %v", err)
	}
}

func TestNewWithoutClientSecret(t *testing.T) {
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	_, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err == nil {
		t.Fatal("expected error for missing client_secret")
	}

	if !strings.Contains(err.Error(), "client_secret is required") {
		t.Errorf("expected error about missing client_secret, got: %v", err)
	}
}

func TestOAuthInitiation(t *testing.T) {
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called during OAuth initiation")
	})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("authenticated"))
	})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", tokenServer.URL+"/oauth/token", accountServer.URL+"/account")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	// Don't set scopes, should use default

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"
	cfg.Scopes = "identity,read"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
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
	encryptedState, err := heroku_oauth_buildpack.EncryptState(state, clientSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt state: %v", err)
	}

	return &http.Cookie{
		Name:  "heroku_oauth_state",
		Value: encryptedState,
	}
}

// Helper function to create an encrypted JWT cookie for testing
func createEncryptedJWTCookie(t *testing.T, claims map[string]interface{}, clientSecret string) *http.Cookie {
	encryptedToken, err := heroku_oauth_buildpack.EncryptJWTClaims(claims, clientSecret)
	if err != nil {
		t.Fatalf("Failed to encrypt JWT claims: %v", err)
	}

	return &http.Cookie{
		Name:  "heroku_oauth_jwt",
		Value: encryptedToken,
	}
}

func TestJWTClaimsEncryptionDecryption(t *testing.T) {
	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "01234567-89ab-cdef-0123-456789abcdef",
		"aud":                "heroku-oauth-app",
		"exp":                int64(1234567890),
		"iat":                int64(1234567890 - 3600),
		"jti":                "2bf3ec81701ec291",
		"access_token":       "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		"token_type":         "Bearer",
		"expires_in":         28799,
		"refresh_token":      "01234567-89ab-cdef-0123-456789abcdef",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": int64(1234567890 + (30 * 24 * 60 * 60)),
	}

	clientSecret := "test-client-secret"

	encrypted, err := heroku_oauth_buildpack.EncryptJWTClaims(claims, clientSecret)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := heroku_oauth_buildpack.DecryptJWTClaims(encrypted, clientSecret)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify all fields match
	if decrypted["access_token"] != claims["access_token"] {
		t.Errorf("AccessToken mismatch: expected %s, got %s", claims["access_token"], decrypted["access_token"])
	}
	if decrypted["token_type"] != claims["token_type"] {
		t.Errorf("TokenType mismatch: expected %s, got %s", claims["token_type"], decrypted["token_type"])
	}
	if decrypted["expires_in"] != claims["expires_in"] {
		t.Errorf("ExpiresIn mismatch: expected %v, got %v", claims["expires_in"], decrypted["expires_in"])
	}
	if decrypted["refresh_token"] != claims["refresh_token"] {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", claims["refresh_token"], decrypted["refresh_token"])
	}
	if decrypted["sub"] != claims["sub"] {
		t.Errorf("UserID mismatch: expected %s, got %s", claims["sub"], decrypted["sub"])
	}
	if decrypted["jti"] != claims["jti"] {
		t.Errorf("SessionNonce mismatch: expected %s, got %s", claims["jti"], decrypted["jti"])
	}
	if decrypted["email"] != claims["email"] {
		t.Errorf("Email mismatch: expected %s, got %s", claims["email"], decrypted["email"])
	}
	if decrypted["teams"] != claims["teams"] {
		t.Errorf("Teams mismatch: expected %s, got %s", claims["teams"], decrypted["teams"])
	}
	if decrypted["exp"] != claims["exp"] {
		t.Errorf("ExpiresAt mismatch: expected %v, got %v", claims["exp"], decrypted["exp"])
	}
}

func TestAuthenticatedRequestWithEncryptedJWT(t *testing.T) {
	cfg := heroku_oauth_buildpack.CreateConfig()
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

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create JWT claims
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "01234567-89ab-cdef-0123-456789abcdef",
		"aud":                "heroku-oauth-app",
		"exp":                now + 3600, // 1 hour from now
		"iat":                now,
		"jti":                "2bf3ec81701ec291",
		"access_token":       "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "01234567-89ab-cdef-0123-456789abcdef",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": now + (30 * 24 * 60 * 60),
	}

	// Create request with encrypted JWT cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedJWTCookie(t, claims, "test-client-secret"))

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

	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	nextCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		nextCalled = true
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("refreshed"))
	})

	handler, err := heroku_oauth_buildpack.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", refreshServer.URL+"/oauth/token", "https://api.heroku.com/account")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired JWT claims with valid refresh token
	now := time.Now().Unix()
	expiredTime := now - 3600                     // 1 hour ago
	refreshExpiresAt := now + (30 * 24 * 60 * 60) // 30 days from now

	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "user-123",
		"aud":                "heroku-oauth-app",
		"exp":                expiredTime,
		"iat":                expiredTime - 3600,
		"jti":                "session-nonce",
		"access_token":       "HRKU-expired-access-token",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "valid-refresh-token",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": refreshExpiresAt,
	}

	// Create request with expired JWT cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedJWTCookie(t, claims, "test-client-secret"))

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

	// Should update the JWT cookie with new access token
	cookies := recorder.Header()["Set-Cookie"]
	tokenCookieUpdated := false
	for _, cookie := range cookies {
		if strings.Contains(cookie, "heroku_oauth_jwt") {
			tokenCookieUpdated = true
			break
		}
	}
	if !tokenCookieUpdated {
		t.Error("expected heroku_oauth_jwt cookie to be updated")
	}
}

func TestTokenRefreshFailure(t *testing.T) {
	// Mock Heroku OAuth refresh endpoint that returns error
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant"}`))
	}))
	defer refreshServer.Close()

	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when refresh fails")
	})

	handler, err := heroku_oauth_buildpack.NewForTesting(ctx, next, cfg, "heroku-oauth-plugin", refreshServer.URL+"/oauth/token", "https://api.heroku.com/account")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired JWT claims with invalid refresh token
	now := time.Now().Unix()
	expiredTime := now - 3600                     // 1 hour ago
	refreshExpiresAt := now + (30 * 24 * 60 * 60) // 30 days from now

	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "user-123",
		"aud":                "heroku-oauth-app",
		"exp":                expiredTime,
		"iat":                expiredTime - 3600,
		"jti":                "session-nonce",
		"access_token":       "HRKU-expired-access-token",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "invalid-refresh-token",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": refreshExpiresAt,
	}

	// Create request with expired JWT cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedJWTCookie(t, claims, "test-client-secret"))

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
		if strings.Contains(cookie, "heroku_oauth_jwt") && (strings.Contains(cookie, "Max-Age=-1") || strings.Contains(cookie, "Max-Age=0")) {
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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when refresh token is expired")
	})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired JWT claims with expired refresh token
	now := time.Now().Unix()
	expiredTime := now - 3600        // 1 hour ago
	expiredRefreshTime := now - 3600 // 1 hour ago

	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "user-123",
		"aud":                "heroku-oauth-app",
		"exp":                expiredTime,
		"iat":                expiredTime - 3600,
		"jti":                "session-nonce",
		"access_token":       "HRKU-expired-access-token",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "expired-refresh-token",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": expiredRefreshTime,
	}

	// Create request with expired JWT cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedJWTCookie(t, claims, "test-client-secret"))

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
	cfg := heroku_oauth_buildpack.CreateConfig()
	cfg.ClientID = "test-client-id"
	cfg.ClientSecret = "test-client-secret"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("next handler should not be called when no refresh token is available")
	})

	handler, err := heroku_oauth_buildpack.New(ctx, next, cfg, "heroku-oauth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// Create expired JWT claims without refresh token
	now := time.Now().Unix()
	expiredTime := now - 3600 // 1 hour ago

	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "user-123",
		"aud":                "heroku-oauth-app",
		"exp":                expiredTime,
		"iat":                expiredTime - 3600,
		"jti":                "session-nonce",
		"access_token":       "HRKU-expired-access-token",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "", // No refresh token
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": int64(0),
	}

	// Create request with expired JWT cookie
	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(createEncryptedJWTCookie(t, claims, "test-client-secret"))

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

func TestJWTClaimsWithRefreshExpiration(t *testing.T) {
	claims := map[string]interface{}{
		"iss":                "heroku-oauth",
		"sub":                "01234567-89ab-cdef-0123-456789abcdef",
		"aud":                "heroku-oauth-app",
		"exp":                int64(1234567890),
		"iat":                int64(1234567890 - 3600),
		"jti":                "2bf3ec81701ec291",
		"access_token":       "HRKU-01234567-89ab-cdef-0123-456789abcdef",
		"token_type":         "Bearer",
		"expires_in":         3600,
		"refresh_token":      "01234567-89ab-cdef-0123-456789abcdef",
		"email":              "test@example.com",
		"teams":              "team1,team2",
		"refresh_expires_at": int64(1234567890 + (30 * 24 * 60 * 60)), // 30 days later
	}

	clientSecret := "test-client-secret"

	encrypted, err := heroku_oauth_buildpack.EncryptJWTClaims(claims, clientSecret)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := heroku_oauth_buildpack.DecryptJWTClaims(encrypted, clientSecret)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify all fields match including refresh expiration field
	if decrypted["access_token"] != claims["access_token"] {
		t.Errorf("AccessToken mismatch: expected %s, got %s", claims["access_token"], decrypted["access_token"])
	}
	if decrypted["token_type"] != claims["token_type"] {
		t.Errorf("TokenType mismatch: expected %s, got %s", claims["token_type"], decrypted["token_type"])
	}
	if decrypted["expires_in"] != claims["expires_in"] {
		t.Errorf("ExpiresIn mismatch: expected %v, got %v", claims["expires_in"], decrypted["expires_in"])
	}
	if decrypted["refresh_token"] != claims["refresh_token"] {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", claims["refresh_token"], decrypted["refresh_token"])
	}
	if decrypted["sub"] != claims["sub"] {
		t.Errorf("UserID mismatch: expected %s, got %s", claims["sub"], decrypted["sub"])
	}
	if decrypted["jti"] != claims["jti"] {
		t.Errorf("SessionNonce mismatch: expected %s, got %s", claims["jti"], decrypted["jti"])
	}
	if decrypted["email"] != claims["email"] {
		t.Errorf("Email mismatch: expected %s, got %s", claims["email"], decrypted["email"])
	}
	if decrypted["teams"] != claims["teams"] {
		t.Errorf("Teams mismatch: expected %s, got %s", claims["teams"], decrypted["teams"])
	}
	if decrypted["exp"] != claims["exp"] {
		t.Errorf("ExpiresAt mismatch: expected %v, got %v", claims["exp"], decrypted["exp"])
	}
	if decrypted["refresh_expires_at"] != claims["refresh_expires_at"] {
		t.Errorf("RefreshExpiresAt mismatch: expected %v, got %v", claims["refresh_expires_at"], decrypted["refresh_expires_at"])
	}
}
