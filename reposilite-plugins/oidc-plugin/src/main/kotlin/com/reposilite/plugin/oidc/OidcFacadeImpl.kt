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

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException
import com.fasterxml.jackson.databind.ObjectMapper
import com.reposilite.ReposiliteObjectMapper
import com.reposilite.journalist.Journalist
import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.api.CreateAccessTokenRequest
import panda.std.reactive.MutableReference
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64

/**
 * Implementation of OidcFacade providing OAuth2/OIDC authentication flow.
 */
class OidcFacadeImpl(
    private val journalist: Journalist,
    private val oidcSettings: MutableReference<OidcSettings>,
    private val accessTokenFacade: AccessTokenFacade
) : OidcFacade {

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(Duration.ofSeconds(30))
        .build()

    // Use shared ObjectMapper from Reposilite to avoid duplicate dependencies
    private val objectMapper: ObjectMapper = ReposiliteObjectMapper.DEFAULT_OBJECT_MAPPER

    private val userSessions = mutableMapOf<String, OidcUserSession>()
    private val secureRandom = SecureRandom()

    // Cached discovered endpoints
    private var discoveredEndpoints: DiscoveredEndpoints? = null
    private var discoveredIssuer: String? = null

    data class DiscoveredEndpoints(
        val authorizationEndpoint: String,
        val tokenEndpoint: String,
        val userinfoEndpoint: String?
    )

    override fun getAuthorizationUrl(): String {
        return generateAuthorizationUrl()
    }

    override fun generateAuthorizationUrl(): String {
        return generateAuthorizationUrlWithPrompt(null)
    }

    private fun generateAuthorizationUrlWithPrompt(prompt: String?): String {
        val settings = oidcSettings.get()

        if (settings.issuer.isBlank()) {
            throw IllegalStateException("OIDC issuer not configured")
        }

        // Generate state for CSRF protection
        val state = generateSecureState()
        val nonce = generateSecureState()

        // Get authorization endpoint (use configured or discover)
        val authEndpoint = getAuthorizationEndpoint()
        val scopes = settings.scopes.split(" ").filter { it.isNotBlank() }.joinToString(" ")

        val params = mutableMapOf(
            "response_type" to "code",
            "client_id" to settings.clientId,
            "redirect_uri" to settings.redirectUri,
            "scope" to scopes,
            "state" to state,
            "nonce" to nonce
        )

        // Add prompt parameter if provided (e.g., "consent" for registration flow)
        if (!prompt.isNullOrBlank()) {
            params["prompt"] = prompt
        }

        val queryString = params.entries.joinToString("&") { "${it.key}=${encodeURIComponent(it.value)}" }
        return "$authEndpoint?$queryString"
    }

    /**
     * Get authorization endpoint, using configured value or auto-discovery
     */
    private fun getAuthorizationEndpoint(): String {
        val settings = oidcSettings.get()

        // Use configured endpoint if available
        if (settings.authorizationEndpoint.isNotBlank()) {
            return settings.authorizationEndpoint
        }

        // Auto-discover endpoints
        val endpoints = discoverEndpoints()
        return endpoints.authorizationEndpoint
    }

    /**
     * Get token endpoint, using configured value or auto-discovery
     */
    private fun getTokenEndpoint(): String {
        val settings = oidcSettings.get()

        // Use configured endpoint if available
        if (settings.tokenEndpoint.isNotBlank()) {
            return settings.tokenEndpoint
        }

        // Auto-discover endpoints
        val endpoints = discoverEndpoints()
        return endpoints.tokenEndpoint
    }

    /**
     * Auto-discover OIDC endpoints from issuer's .well-known/openid-configuration
     */
    @Suppress("UNCHECKED_CAST")
    private fun discoverEndpoints(): DiscoveredEndpoints {
        val settings = oidcSettings.get()

        if (settings.issuer.isBlank()) {
            throw IllegalStateException("OIDC issuer not configured")
        }

        // Clear cache if issuer changed
        if (discoveredIssuer != settings.issuer) {
            discoveredEndpoints = null
            discoveredIssuer = settings.issuer
        }

        // Return cached endpoints if available
        discoveredEndpoints?.let { return it }

        val discoveryUrl = "${settings.issuer.removeSuffix("/")}/.well-known/openid-configuration"

        journalist.logger.debug("[OIDC] Discovering endpoints from: $discoveryUrl")

        val request = HttpRequest.newBuilder()
            .uri(URI.create(discoveryUrl))
            .header("Accept", "application/json")
            .GET()
            .build()

        try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() != 200) {
                journalist.logger.debug("[OIDC] Discovery failed with status: ${response.statusCode()}")
                throw IllegalStateException("Failed to fetch OIDC discovery document")
            }

            val discoveryBody = response.body()
            journalist.logger.debug("[OIDC] Discovery response: $discoveryBody")

            val discovery = objectMapper.readValue(discoveryBody, Map::class.java) as Map<String, Any>

            val authEndpoint = (discovery["authorization_endpoint"] as? String)
                ?: throw IllegalStateException("authorization_endpoint not found in discovery document")

            val tokenEndpoint = (discovery["token_endpoint"] as? String)
                ?: throw IllegalStateException("token_endpoint not found in discovery document")

            val userinfoEndpoint = discovery["userinfo_endpoint"] as? String

            val endpoints = DiscoveredEndpoints(
                authorizationEndpoint = authEndpoint,
                tokenEndpoint = tokenEndpoint,
                userinfoEndpoint = userinfoEndpoint
            )

            // Cache the discovered endpoints
            discoveredEndpoints = endpoints

            journalist.logger.debug("[OIDC] Discovered endpoints - Auth: $authEndpoint, Token: $tokenEndpoint")

            return endpoints
        } catch (e: Exception) {
            journalist.logger.debug("[OIDC] Endpoint discovery failed: ${e.message}")
            throw IllegalStateException("Failed to discover OIDC endpoints: ${e.message}")
        }
    }

    /**
     * Clear cached endpoints (useful when issuer changes)
     */
    override fun clearDiscoveredEndpoints() {
        discoveredEndpoints = null
        discoveredIssuer = null
    }

    @Suppress("UNCHECKED_CAST")
    override fun handleCallback(code: String): OidcUserSession {
        val settings = oidcSettings.get()

        if (!settings.enabled) {
            throw IllegalStateException("OIDC authentication is disabled")
        }

        if (code.isBlank()) {
            throw IllegalArgumentException("Authorization code is required")
        }

        // Exchange authorization code for tokens
        val tokenResponse = exchangeCodeForTokens(code)
            ?: throw IllegalStateException("Failed to exchange code for tokens")

        val accessToken = tokenResponse["access_token"]?.toString()
            ?: throw IllegalStateException("No access_token in response")

        val idToken = tokenResponse["id_token"]?.toString()
            ?: throw IllegalStateException("No id_token in response")

        val expiresIn = tokenResponse["expires_in"]?.toString()?.toLongOrNull() ?: 3600L

        // Decode ID Token to get user info
        val decodedJWT = try {
            JWT.decode(idToken)
        } catch (e: JWTDecodeException) {
            throw IllegalStateException("Invalid ID token: ${e.message}")
        }

        val userId = decodedJWT.getClaim(settings.userIdClaim).asString()
            ?: decodedJWT.subject
            ?: throw IllegalStateException("Cannot determine user ID from token")

        val username = decodedJWT.getClaim(settings.usernameClaim).asString()
            ?: decodedJWT.getClaim("name")?.asString()
            ?: decodedJWT.getClaim("email")?.asString()?.substringBefore("@")
            ?: userId

        val email = decodedJWT.getClaim("email")?.asString()

        val expiresAt = Instant.now().epochSecond + expiresIn

        val session = OidcUserSession(
            userId = userId,
            username = username,
            email = email,
            accessToken = accessToken,
            idToken = idToken,
            expiresAt = expiresAt
        )

        // Store session
        userSessions[userId] = session

        // Optionally create access token
        if (settings.autoCreateUsers) {
            try {
                val existingToken = accessTokenFacade.getAccessToken(username)
                if (existingToken == null) {
                    accessTokenFacade.createAccessToken(
                        CreateAccessTokenRequest(
                            type = com.reposilite.token.AccessTokenType.PERSISTENT,
                            name = username,
                            secret = accessToken
                        )
                    )
                    journalist.logger.debug("[OIDC] Auto-created access token for user: $username")
                }
            } catch (e: Exception) {
                journalist.logger.debug("[OIDC] Failed to create access token for $username: ${e.message}")
            }
        }

        return session
    }

    @Suppress("UNCHECKED_CAST")
    private fun exchangeCodeForTokens(code: String): Map<String, Any>? {
        // Get token endpoint (use configured or discover)
        val tokenEndpoint = getTokenEndpoint()

        val settings = oidcSettings.get()

        val requestBody = mapOf(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to settings.redirectUri,
            "client_id" to settings.clientId,
            "client_secret" to settings.clientSecret
        )

        val bodyParams = requestBody.entries.joinToString("&") { "${it.key}=${encodeURIComponent(it.value)}" }

        val request = HttpRequest.newBuilder()
            .uri(URI.create(tokenEndpoint))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(bodyParams))
            .build()

        return try {
            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) {
                journalist.logger.debug("[OIDC] Token exchange failed: ${response.body()}")
                return null
            }

            val responseBody = response.body()
            journalist.logger.debug("[OIDC] Token exchange response: $responseBody")

            // Parse JSON response using Jackson
            objectMapper.readValue(responseBody, Map::class.java) as? Map<String, Any>
        } catch (e: Exception) {
            journalist.logger.debug("[OIDC] Token exchange error: ${e.message}")
            null
        }
    }

    override fun getCurrentSession(accessToken: String): OidcUserSession? {
        val settings = oidcSettings.get()

        // Handle Bearer token format
        val token = if (accessToken.startsWith(settings.tokenType, ignoreCase = true)) {
            accessToken.substringAfter(" ").trim()
        } else {
            accessToken
        }

        // Try to find session by access token
        return userSessions.values.find { it.accessToken == token || it.idToken == token }
    }

    fun createAuthenticator(): OidcAuthenticator {
        return OidcAuthenticator(
            journalist = journalist,
            oidcSettings = oidcSettings,
            accessTokenFacade = accessTokenFacade,
            oidcFacade = this
        )
    }

    override fun getOidcSettings(): OidcSettings = oidcSettings.get()

    private fun generateSecureState(): String {
        val bytes = ByteArray(32)
        secureRandom.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun encodeURIComponent(value: String): String {
        return URLEncoder.encode(value, "UTF-8")
            .replace("+", "%20")
            .replace("%7E", "~")
    }
}
