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

    override fun getAuthorizationUrl(): String {
        return generateAuthorizationUrl()
    }

    override fun generateAuthorizationUrl(): String {
        val settings = oidcSettings.get()

        if (settings.issuer.isBlank()) {
            throw IllegalStateException("OIDC issuer not configured")
        }

        // Generate state for CSRF protection
        val state = generateSecureState()

        // Build authorization URL
        val authEndpoint = "${settings.issuer.removeSuffix("/")}/protocol/openid-connect/auth"
        val scopes = settings.scopes.split(" ").filter { it.isNotBlank() }.joinToString(" ")

        val params = mapOf(
            "client_id" to settings.clientId,
            "redirect_uri" to settings.redirectUri,
            "response_type" to "code",
            "scope" to scopes,
            "state" to state
        )

        val queryString = params.entries.joinToString("&") { "${it.key}=${encodeURIComponent(it.value)}" }
        return "$authEndpoint?$queryString"
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
        val settings = oidcSettings.get()

        val tokenEndpoint = "${settings.issuer.removeSuffix("/")}/protocol/openid-connect/token"

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
