# OIDC Plugin

OpenID Connect (OIDC) authentication plugin for Reposilite.

## Features

- OAuth2 Authorization Code Flow with PKCE support
- Bearer Token authentication for API requests
- JWT ID Token validation
- Automatic user provisioning
- Integration with existing Reposilite authentication system

## Configuration

Add the following to your `configuration.yml`:

```yaml
oidc:
  enabled: true
  issuer: "https://your-idp.example.com"
  clientId: "reposilite"
  clientSecret: "your-client-secret"
  redirectUri: "http://localhost:8080/api/auth/oidc/callback"
  scopes: "openid profile email"
  tokenType: "Bearer"
  userIdClaim: "sub"
  usernameClaim: "preferred_username"
  autoCreateUsers: true
  verifyIssuer: true
  clockSkewSeconds: 60
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `enabled` | Enable/disable OIDC authentication | `false` |
| `issuer` | OIDC Provider URL | `""` |
| `clientId` | OAuth2 Client ID | `""` |
| `clientSecret` | OAuth2 Client Secret | `""` |
| `redirectUri` | Callback URL after authentication | `""` |
| `scopes` | Space-separated OAuth2 scopes | `"openid profile email"` |
| `tokenType` | Expected token type in Authorization header | `"Bearer"` |
| `userIdClaim` | JWT claim name for user identifier | `"sub"` |
| `usernameClaim` | JWT claim name for username | `"preferred_username"` |
| `autoCreateUsers` | Automatically create access tokens for authenticated users | `true` |
| `verifyIssuer` | Verify JWT issuer matches configured issuer | `true` |
| `clockSkewSeconds` | Allowed clock skew in seconds for JWT validation | `60` |

## API Endpoints

### Initiate Login

```http
GET /api/auth/oidc/login
```

Redirects the user to the OIDC provider for authentication.

### Callback Handler

```http
GET /api/auth/oidc/callback?code={authorization_code}
```

Handles the OAuth2 callback from the OIDC provider.

**Query Parameters:**
- `code` - Authorization code (required)
- `error` - Error code if authentication failed
- `error_description` - Error description

**Response (success):**
```json
{
  "success": true,
  "user": {
    "id": "user-123",
    "username": "john.doe",
    "email": "john@example.com"
  },
  "expires_at": 1707187200
}
```

### Get Current User

```http
GET /api/auth/oidc/user
Authorization: Bearer {access_token}
```

Returns information about the currently authenticated OIDC user.

### Get OIDC Configuration

```http
GET /api/auth/oidc/configuration
```

Returns the configured OIDC provider configuration.

## Usage

### OAuth2 Authorization Code Flow

1. Redirect user to `/api/auth/oidc/login`
2. User authenticates with the OIDC provider
3. Provider redirects to `/api/auth/oidc/callback?code=xxx`
4. Exchange code for tokens and create Reposilite session
5. Use the returned access token for subsequent requests

### Bearer Token Authentication

Send API requests with the ID Token in the Authorization header:

```http
GET /api/tokens
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Supported OIDC Providers

- Keycloak
- Auth0
- Okta
- Google Identity Platform
- Azure Active Directory
- Any OIDC-compliant provider

## Building

```bash
./gradlew :reposilite-plugins:oidc-plugin:build
```

The built JAR will be in `reposilite-test/workspace/plugins/oidc-plugin.jar`.
