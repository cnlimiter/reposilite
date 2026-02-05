/*
 * Copyright (c) 2024 Reposilite
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.reposilite.plugin.oidc

import com.reposilite.configuration.shared.api.Doc
import com.reposilite.configuration.shared.api.SharedSettings
import io.javalin.openapi.JsonSchema

@JsonSchema(requireNonNulls = false)
@Doc(title = "OIDC", description = "OpenID Connect Authentication settings")
data class OidcSettings(
    @get:Doc(title = "Enabled", description = "OIDC Authentication is enabled")
    val enabled: Boolean = false,

    @get:Doc(title = "Issuer", description = "OIDC Provider URL (e.g., https://your-idp.example.com)")
    val issuer: String = "",

    @get:Doc(title = "Client ID", description = "OAuth2 Client ID")
    val clientId: String = "",

    @get:Doc(title = "Client Secret", description = "OAuth2 Client Secret")
    val clientSecret: String = "",

    @get:Doc(title = "Redirect URI", description = "Callback URL after authentication")
    val redirectUri: String = "",

    @get:Doc(title = "Scopes", description = "Requested OAuth2 scopes (space-separated or list)")
    val scopes: String = "openid profile email",

    @get:Doc(title = "Token Type", description = "Expected token type in Authorization header")
    val tokenType: String = "Bearer",

    @get:Doc(title = "User ID Claim", description = "JWT claim name for user identifier")
    val userIdClaim: String = "sub",

    @get:Doc(title = "Username Claim", description = "JWT claim name for username")
    val usernameClaim: String = "preferred_username",

    @get:Doc(title = "Auto-create Users", description = "Automatically create access tokens for authenticated users")
    val autoCreateUsers: Boolean = true,

    @get:Doc(title = "Issuer Verification", description = "Verify JWT issuer matches configured issuer")
    val verifyIssuer: Boolean = true,

    @get:Doc(title = "Clock Skew Seconds", description = "Allowed clock skew in seconds for JWT validation")
    val clockSkewSeconds: Int = 60
) : SharedSettings
