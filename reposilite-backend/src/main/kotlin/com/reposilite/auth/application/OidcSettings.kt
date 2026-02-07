/*
 * Copyright (c) 2023 dzikoysk
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

package com.reposilite.auth.application

import com.reposilite.configuration.shared.api.Doc
import com.reposilite.configuration.shared.api.SharedSettings
import com.reposilite.token.AccessTokenType
import com.reposilite.token.AccessTokenType.PERSISTENT

@Doc(title = "OIDC", description = "OpenID Connect Authenticator settings")
data class OidcSettings(
    @get:Doc(title = "Enabled", description = "OIDC Authenticator is enabled")
    val enabled: Boolean = false,
    @get:Doc(title = "Issuer", description = "OIDC provider issuer URL (e.g., https://your-keycloak-server.com/realms/your-realm)")
    val issuer: String = "",
    @get:Doc(title = "Client ID", description = "Client ID registered with the OIDC provider")
    val clientId: String = "",
    @get:Doc(title = "Client Secret", description = "Client secret registered with the OIDC provider")
    val clientSecret: String = "",
    @get:Doc(title = "Redirect URI", description = "Callback URL where the OIDC provider will redirect after authentication")
    val redirectUri: String = "",
    @get:Doc(title = "Scope", description = "OIDC scope parameter (space-separated)")
    val scope: String = "openid profile email",
    @get:Doc(title = "Token Type", description = "Should the created through OIDC access token be TEMPORARY or PERSISTENT")
    val tokenType: AccessTokenType = PERSISTENT,
    @get:Doc(title = "Default Permission", description = "Default permission for new OIDC users")
    val defaultPermission: String? = null,
    @get:Doc(title = "Require Verified Email", description = "Require email to be verified by OIDC provider")
    val requireVerifiedEmail: Boolean = false,
    @get:Doc(title = "Use Discovery", description = "Automatically discover OIDC endpoints from /.well-known/openid-configuration")
    val useDiscovery: Boolean = true,
    @get:Doc(title = "Authorization Endpoint", description = "OIDC authorization endpoint (auto-discovered if useDiscovery is true)")
    val authorizationEndpoint: String = "",
    @get:Doc(title = "Token Endpoint", description = "OIDC token endpoint (auto-discovered if useDiscovery is true)")
    val tokenEndpoint: String = "",
    @get:Doc(title = "UserInfo Endpoint", description = "OIDC UserInfo endpoint (auto-discovered if useDiscovery is true)")
    val userInfoEndpoint: String = "",
    @get:Doc(title = "JWKS URI", description = "OIDC JWKS URI for token verification (auto-discovered if useDiscovery is true)")
    val jwksUri: String = ""
) : SharedSettings
