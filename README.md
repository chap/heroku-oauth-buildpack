# Heroku OAuth Buildpack

Adds Heroku OAuth in front of an app.

## Quickstart

Create simple config to protect /admin* paths

```term
mkdir -p .heroku/
echo 'spec:
  proxy:
    - path: /admin*
      plugins:
        - source: github.com/chap/heroku-oauth-buildpack' > .heroku/app3.yaml
```

[Create OAuth Client](https://dashboard.heroku.com/account/applications/clients/new)

Copy OAuth Client variables to app

```term
$ heroku config:add HEROKU_OAUTH_CLIENT_ID=<client-id> HEROKU_OAUTH_CLIENT_SECRET=<client-secret> -a <my-app>
```

Install buildpack

```term
$ heroku buildpacks:add https://heroku-oauth-buildpack-staging- -a <my-app>
```

Rebuild app

```term
$ git add .heroku/app.yaml
$ git commit .heroku/app.yaml -m "add heroku oauth configuration"
$ git push heroku
```

Test request

```term
$ curl <my-app-rand>.herokuapp.com/admin -i
```

Restrict to an email address domain:
```yaml
- path: /*
  plugins:
    - source: github.com/chap/heroku-oauth-buildpack
      config:
        domain: heroku.com
```

## App Integration

Heroku token is stored encrypted in a cookie. It can be read by a downstream client using `HEROKU_OAUTH_CLIENT_SECRET`.

Minimal Sinatra example demonstrating cookie decryption and accessing user info:

```ruby
require 'sinatra'
require 'openssl'
require 'base64'
require 'json'

def decrypt_heroku_token(encrypted_data)
  ciphertext = Base64.urlsafe_decode64(encrypted_data)
  key        = OpenSSL::Digest::SHA256.digest(ENV['HEROKU_OAUTH_CLIENT_SECRET'])
  
  # Extract nonce and authentication tag
  nonce      = ciphertext[0, 12]
  tag        = ciphertext[-16..-1]
  ciphertext = ciphertext[12...-16]
  
  # Decrypt
  cipher          = OpenSSL::Cipher.new('aes-256-gcm')
  cipher.decrypt
  cipher.key      = key
  cipher.iv       = nonce
  cipher.auth_tag = tag
  
  decrypted = cipher.update(ciphertext) + cipher.final
  JSON.parse(decrypted)
end

get '/admin' do
  encrypted_token = request.cookies['heroku_oauth_token']
  token_data = decrypt_heroku_token(encrypted_token)
  
  "Hello #{token_data['email']}"
end
```

## Features

- Completely contained Heroku OAuth 2.0 web application authorization flow
- Secure state parameter validation to prevent CSRF attacks
- Automatic OAuth token refresh
- Session management using encrypted HTTP cookies
- Email address filtering

### Environment Variables

Configure setup

- `HEROKU_OAUTH_CLIENT_ID`: Your Heroku OAuth application client ID (required)
- `HEROKU_OAUTH_CLIENT_SECRET`: Your Heroku OAuth application client secret (required)
- `HEROKU_MANIFEST_FILENAME`: Path to configuration file (default: .heroku/app.yaml)

## How It Works

### OAuth Flow

1. **Initial Request**: When a user makes a request to your application that matches the proxy rule, the plugin checks if they're authenticated
2. **Redirect to Heroku**: If not authenticated, the user is redirected to Heroku's OAuth authorization page
3. **User Authorization**: The user logs in to Heroku and authorizes your application
4. **Callback Handling**: Heroku redirects back to the configured callback path with an authorization code
5. **Token Exchange**: The plugin exchanges the authorization code for an access token and refresh token
6. **User Info Retrieval**: The plugin fetches the user's account information from Heroku API
7. **Session Creation**: The user's email and tokens are stored in secure HTTP cookies
8. **Request Processing**: Subsequent requests include the `X-DYNO-PROXY-HEROKU-EMAIL` header

### Token Refresh Flow

When an access token expires, the plugin automatically handles token refresh:

1. **Token Expiration Check**: On each request, the plugin checks if the access token has expired
2. **Refresh Token Validation**: If expired, the plugin checks if a valid refresh token exists
3. **Automatic Refresh**: If a valid refresh token is available, the plugin automatically exchanges it for a new access token
4. **Seamless Continuation**: The request continues with the new access token without user intervention
5. **Fallback to OAuth**: If refresh fails or no refresh token is available, the user is redirected to re-authenticate

This ensures users don't need to re-authenticate frequently, providing a smooth user experience while maintaining security.

### State Parameter Security

The OAuth state parameter is a critical security feature that prevents Cross-Site Request Forgery (CSRF) attacks:

1. **Generation**: A cryptographically secure 32-byte random value is generated using `crypto/rand`
2. **Encryption**: The state is encrypted using AES-256-GCM with the client secret as the encryption key
3. **Storage**: The encrypted state is stored in a secure HTTP-only cookie
4. **Validation**: On callback, the state from the URL is compared with the decrypted state from the cookie
5. **Cleanup**: The state cookie is cleared after successful validation

This approach ensures that only the legitimate OAuth flow can complete successfully, preventing malicious sites from initiating unauthorized OAuth requests.

### Stateless Session Management

Unlike traditional session management that requires external storage (Redis, databases), this implementation uses encrypted cookies:

- **Encryption**: All session data (tokens, user info, teams) is encrypted using AES-256-GCM
- **Self-contained**: Each cookie contains all necessary information, eliminating server-side session storage
- **Scalable**: No shared state between application instances, enabling horizontal scaling
- **Secure**: Data is encrypted with the client secret, making it tamper-proof
- **Stateless**: Each request is independent, reducing infrastructure complexity

### Security Features

- **State Parameter**: Each OAuth request includes a cryptographically secure random state parameter to prevent CSRF attacks. The state is encrypted using AES-256-GCM with the client secret as the key and stored in a secure cookie.
- **Secure Cookies**: Authentication cookies are marked as HttpOnly and Secure (when using HTTPS)
- **SameSite Protection**: Cookies use SameSite=Lax to prevent cross-site request forgery
- **Encrypted Session Storage**: All session data (tokens, user info) is encrypted using AES-256-GCM before being stored in cookies, eliminating the need for external session storage

### Headers

Once authenticated, all proxy requests will include:

```
X-DYNO-PROXY-HEROKU-EMAIL: user@example.com
```


## Error Handling

The plugin handles various error scenarios:

- **Missing Credentials**: Returns error if client_id or client_secret are not provided
- **OAuth Errors**: Handles Heroku OAuth errors (e.g., user denies access)
- **Invalid State**: Validates state parameter to prevent CSRF attacks
- **API Errors**: Handles errors from Heroku API calls
- **Network Timeouts**: Includes 30-second timeouts for external API calls

## Testing

The plugin includes comprehensive tests covering:

- Configuration validation
- OAuth initiation flow
- Callback handling
- Error scenarios
- Header injection
- Scope configuration

Run tests with:
```bash
# Run Go tests
go test ./plugins/heroku-oauth/...

# Run compile script tests
make test-compile
# Or run directly:
./tests/buildpack-compile
```



## Troubleshooting

### Common Issues

- **"client_id is required" error**
   - Ensure `HEROKU_OAUTH_CLIENT_ID` environment variable is set
   - Or provide `client_id` in the plugin configuration

- **"client_secret is required" error**
   - Ensure `HEROKU_OAUTH_CLIENT_SECRET` environment variable is set
   - Or provide `client_secret` in the plugin configuration

- **Callback URL mismatch**
   - Ensure your Heroku OAuth application's proxy URL matches your domain
   - Ensure
   - Format: `https://your-domain.com/<my-path>/callback`

### Logging

Set `HEROKU_OAUTH_LOG_LEVEL=INFO` to send login, logout, and token checks in stdout. User's email, id, and request-id will be logged together in Traefik-style format:

```
2024-01-15T10:30:45.123Z INFO LOGIN user_email=user@example.com user_id=12345 request_id=abc123 url=/admin/callback
2024-01-15T10:30:50.456Z INFO TOKEN_CHECK user_email=user@example.com user_id=12345 request_id=def456 url=/admin/dashboard
2024-01-15T10:31:00.789Z INFO LOGOUT user_email=user@example.com user_id=12345 request_id=ghi789 url=/admin?heroku-oauth-logout=true
```

The logging includes:
- **LOGIN**: When a user successfully authenticates via OAuth callback
- **TOKEN_CHECK**: When the system validates an existing token on each request
- **LOGOUT**: When a user logs out via the logout parameter

Each log entry includes:
- `user_email`: The authenticated user's email address
- `user_id`: The authenticated user's Heroku ID
- `request_id`: The X-Request-ID header value (or "unknown" if not present)
- `url`: The full request URL

Set `HEROKU_OAUTH_LOG_LEVEL=DEBUG` for additional setup and debugging information.


## Next

- Restrict access by team or app roles.
  - would require `read` scope. does that allow config var reading?
