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

package com.reposilite.auth.infrastructure

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.reposilite.auth.application.OidcSettings
import com.reposilite.journalist.Journalist
import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.api.CreateAccessTokenRequest
import com.reposilite.web.api.ReposiliteRoute
import com.reposilite.web.api.ReposiliteRoutes
import com.reposilite.web.routing.RouteMethod
import io.javalin.community.routing.Route
import io.javalin.openapi.HttpMethod
import io.javalin.openapi.OpenApi
import io.javalin.openapi.OpenApiContent
import io.javalin.openapi.OpenApiParam
import io.javalin.openapi.OpenApiResponse
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import panda.std.Result
import panda.std.Result.ok
import panda.std.reactive.Reference
import java.io.IOException
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * OIDC Authentication Endpoints
 * Provides endpoints for OIDC login flow: configuration, login initiation, and callback handling
 * Uses OpenID Connect Discovery (/.well-known/openid-configuration) for automatic endpoint discovery
 */
internal class OidcEndpoints(
    private val journalist: Journalist,
    private val oidcSettings: Reference<OidcSettings>,
    private val accessTokenFacade: AccessTokenFacade
) : ReposiliteRoutes() {

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
            .build()
    }

    private val objectMapper = ObjectMapper()
    private val secureRandom = SecureRandom()

    // Discovery document cache
    private var cachedDiscovery: DiscoveryDocument? = null

    @OpenApi(
        path = "/api/auth/oidc/configuration",
        methods = [HttpMethod.GET],
        summary = "Get OIDC configuration status",
        description = "Returns the current OIDC configuration status",
        tags = ["Auth"],
        responses = [
            OpenApiResponse(
                status = "200",
                description = "OIDC configuration details",
                content = [OpenApiContent(from = OidcConfigurationResponse::class)]
            )
        ]
    )
    private val configuration = ReposiliteRoute<OidcConfigurationResponse>(
        "/api/auth/oidc/configuration",
        Route.GET
    ) {
        val settings = oidcSettings.get()
        response = ok(OidcConfigurationResponse(
            enabled = settings.enabled,
            issuer = if (settings.enabled) settings.issuer else null,
            useDiscovery = settings.useDiscovery,
            authorizationEndpoint = getAuthorizationEndpoint(settings),
            tokenEndpoint = getTokenEndpoint(settings),
            userInfoEndpoint = getUserInfoEndpoint(settings),
            jwksUri = getJwksUri(settings)
        ))
    }

    @OpenApi(
        path = "/api/auth/oidc/login",
        methods = [HttpMethod.GET],
        summary = "Initiate OIDC login",
        description = "Redirects to the OIDC Provider for authentication",
        tags = ["Auth"],
        responses = [
            OpenApiResponse(
                status = "302",
                description = "Redirect to OIDC Provider authorization page"
            )
        ]
    )
    private val login = ReposiliteRoute<Unit>(
        "/api/auth/oidc/login",
        Route.GET
    ) {
        val settings = oidcSettings.get()
        if (!settings.enabled) {
            ctx.redirect("/")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        // Generate state for CSRF protection
        val state = generateState()
        ctx.sessionAttribute("oidc_state", state)
        ctx.sessionAttribute("oidc_redirect", ctx.queryParam("redirect") ?: "/")

        val authUrl = buildAuthorizationUrl(settings, state)
        journalist.logger.debug("[OIDC] Redirecting to authorization URL: $authUrl")
        ctx.redirect(authUrl)
        response = ok(Unit)
    }

    @OpenApi(
        path = "/api/auth/oidc/callback",
        methods = [HttpMethod.GET],
        summary = "OIDC callback handler",
        description = "Handles the callback from OIDC Provider after user authentication",
        tags = ["Auth"],
        queryParams = [
            OpenApiParam(name = "code", description = "Authorization code from OIDC Provider"),
            OpenApiParam(name = "state", description = "State parameter for CSRF protection")
        ],
        responses = [
            OpenApiResponse(
                status = "302",
                description = "Redirect to home page on success or error page on failure"
            )
        ]
    )
    private val callback = ReposiliteRoute<Unit>(
        "/api/auth/oidc/callback",
        Route.GET
    ) {
        val code = ctx.queryParam("code")
        val state = ctx.queryParam("state")

        // Validate state (CSRF protection)
        val storedState = ctx.sessionAttribute<String>("oidc_state")
        val redirectUri = ctx.sessionAttribute<String>("oidc_redirect") ?: "/"

        if (state != storedState || storedState == null) {
            journalist.logger.warn("[OIDC] State mismatch - possible CSRF attack")
            ctx.redirect("/?error=state_mismatch")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        // Clear session state
        ctx.sessionAttribute("oidc_state", null)
        ctx.sessionAttribute("oidc_redirect", null)

        if (code == null) {
            journalist.logger.warn("[OIDC] No authorization code received")
            ctx.redirect("/?error=no_code")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        val settings = oidcSettings.get()

        // Exchange authorization code for tokens
        val tokenResponse = exchangeCodeForTokens(code, settings)
        if (tokenResponse == null) {
            journalist.logger.warn("[OIDC] Failed to exchange authorization code for tokens")
            ctx.redirect("/?error=token_exchange_failed")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        // Get UserInfo from OIDC Provider
        val userInfo = fetchUserInfo(tokenResponse.accessToken, settings)
        if (userInfo == null) {
            journalist.logger.warn("[OIDC] Failed to fetch UserInfo")
            ctx.redirect("/?error=user_info_failed")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        // Extract username from UserInfo
        val username = extractUsername(userInfo)
        if (username == null) {
            journalist.logger.warn("[OIDC] No username found in UserInfo")
            ctx.redirect("/?error=no_username")
            response = ok(Unit)
            return@ReposiliteRoute
        }

        journalist.logger.debug("[OIDC] User authenticated: $username")

        // Create or get existing AccessToken
        val existingToken = accessTokenFacade.getAccessToken(username)
        val (tokenName, tokenSecret) = if (existingToken != null) {
            existingToken.name to null
        } else {
            val result = accessTokenFacade.createAccessToken(
                CreateAccessTokenRequest(
                    type = settings.tokenType,
                    name = username,
                    secret = generateSecret()
                )
            )
            result.accessToken.name to result.secret
        }

        // Set authentication cookie
        ctx.cookie("reposilite_auth", "${tokenName}:${tokenSecret}")
        ctx.cookie("reposilite_auth_username", tokenName)

        journalist.logger.debug("[OIDC] Login successful for user: $username")
        ctx.redirect(redirectUri)
        response = ok(Unit)
    }

    override val routes = routes(configuration, login, callback)

    /**
     * Get authorization endpoint (from discovery or config)
     */
    private fun getAuthorizationEndpoint(settings: OidcSettings): String {
        return if (settings.useDiscovery) {
            fetchDiscovery(settings)?.authorizationEndpoint ?: settings.authorizationEndpoint
        } else {
            settings.authorizationEndpoint
        }
    }

    /**
     * Get token endpoint (from discovery or config)
     */
    private fun getTokenEndpoint(settings: OidcSettings): String {
        return if (settings.useDiscovery) {
            fetchDiscovery(settings)?.tokenEndpoint ?: settings.tokenEndpoint
        } else {
            settings.tokenEndpoint
        }
    }

    /**
     * Get UserInfo endpoint (from discovery or config)
     */
    private fun getUserInfoEndpoint(settings: OidcSettings): String {
        return if (settings.useDiscovery) {
            fetchDiscovery(settings)?.userInfoEndpoint ?: settings.userInfoEndpoint
        } else {
            settings.userInfoEndpoint
        }
    }

    /**
     * Get JWKS URI (from discovery or config)
     */
    private fun getJwksUri(settings: OidcSettings): String {
        return if (settings.useDiscovery) {
            fetchDiscovery(settings)?.jwksUri ?: settings.jwksUri
        } else {
            settings.jwksUri
        }
    }

    /**
     * Fetch OIDC Discovery Document from /.well-known/openid-configuration
     */
    private fun fetchDiscovery(settings: OidcSettings): DiscoveryDocument? {
        // Return cached discovery if available
        cachedDiscovery?.let { return it }

        if (settings.issuer.isBlank()) {
            journalist.logger.warn("[OIDC] Cannot fetch discovery document: issuer is empty")
            return null
        }

        val discoveryUrl = "${settings.issuer}/.well-known/openid-configuration"
        journalist.logger.debug("[OIDC] Fetching discovery document from: $discoveryUrl")

        val request = Request.Builder()
            .url(discoveryUrl)
            .get()
            .build()

        return try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    journalist.logger.warn("[OIDC] Failed to fetch discovery document: HTTP ${response.code}")
                    return null
                }
                val body = response.body?.string() ?: return null
                val json = objectMapper.readTree(body)

                val discovery = DiscoveryDocument(
                    authorizationEndpoint = json.path("authorization_endpoint").asText(),
                    tokenEndpoint = json.path("token_endpoint").asText(),
                    userInfoEndpoint = json.path("userinfo_endpoint").asText(),
                    jwksUri = json.path("jwks_uri").asText(),
                    issuer = json.path("issuer").asText()
                )

                // Cache the discovery document
                cachedDiscovery = discovery
                journalist.logger.debug("[OIDC] Successfully fetched discovery document")
                discovery
            }
        } catch (e: IOException) {
            journalist.logger.warn("[OIDC] Failed to fetch discovery document: ${e.message}")
            null
        }
    }

    /**
     * Invalidate cached discovery document (useful when issuer changes)
     */
    fun invalidateCache() {
        cachedDiscovery = null
    }

    /**
     * Build OAuth2 authorization URL
     */
    private fun buildAuthorizationUrl(settings: OidcSettings, state: String): String {
        val authEndpoint = getAuthorizationEndpoint(settings)
        if (authEndpoint.isBlank()) {
            throw IllegalStateException("Authorization endpoint is not configured")
        }

        val clientId = URLEncoder.encode(settings.clientId, StandardCharsets.UTF_8)
        val redirectUri = URLEncoder.encode(settings.redirectUri, StandardCharsets.UTF_8)
        val scope = URLEncoder.encode(settings.scope, StandardCharsets.UTF_8)
        val encodedState = URLEncoder.encode(state, StandardCharsets.UTF_8)

        return buildString {
            append(authEndpoint)
            append("?client_id=").append(clientId)
            append("&redirect_uri=").append(redirectUri)
            append("&response_type=code")
            append("&scope=").append(scope)
            append("&state=").append(encodedState)
        }
    }

    /**
     * Exchange authorization code for access token
     */
    private fun exchangeCodeForTokens(code: String, settings: OidcSettings): TokenResponse? {
        val tokenEndpoint = getTokenEndpoint(settings)
        if (tokenEndpoint.isBlank()) {
            journalist.logger.warn("[OIDC] Token endpoint is not configured")
            return null
        }

        val formBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("code", code)
            .add("redirect_uri", settings.redirectUri)
            .add("client_id", settings.clientId)
            .add("client_secret", settings.clientSecret)
            .build()

        val request = Request.Builder()
            .url(tokenEndpoint)
            .post(formBody)
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .build()

        return try {
            httpClient.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) {
                    journalist.logger.debug("[OIDC] Token exchange failed: HTTP ${resp.code}")
                    return null
                }
                val body = resp.body?.string() ?: return null
                val json = objectMapper.readTree(body)

                TokenResponse(
                    accessToken = json.path("access_token").asText(),
                    idToken = if (json.has("id_token") && !json.path("id_token").isNull) json.path("id_token").asText() else null,
                    tokenType = if (json.has("token_type") && !json.path("token_type").isNull) json.path("token_type").asText() else "Bearer",
                    expiresIn = if (json.has("expires_in") && !json.path("expires_in").isNull) json.path("expires_in").asInt() else 0
                )
            }
        } catch (e: IOException) {
            journalist.logger.debug("[OIDC] Token exchange error: ${e.message}")
            null
        }
    }

    /**
     * Fetch UserInfo from OIDC Provider
     */
    private fun fetchUserInfo(accessToken: String, settings: OidcSettings): JsonNode? {
        val userInfoUrl = getUserInfoEndpoint(settings)
        if (userInfoUrl.isBlank()) {
            journalist.logger.warn("[OIDC] UserInfo endpoint is not configured")
            return null
        }

        val request = Request.Builder()
            .url(userInfoUrl)
            .addHeader("Authorization", "Bearer $accessToken")
            .get()
            .build()

        return try {
            httpClient.newCall(request).execute().use { resp ->
                if (!resp.isSuccessful) {
                    journalist.logger.debug("[OIDC] UserInfo fetch failed: HTTP ${resp.code}")
                    return null
                }
                val body = resp.body?.string() ?: return null
                objectMapper.readTree(body)
            }
        } catch (e: IOException) {
            journalist.logger.debug("[OIDC] UserInfo fetch error: ${e.message}")
            null
        }
    }

    /**
     * Extract username from UserInfo response
     */
    private fun extractUsername(userInfo: JsonNode): String? {
        return userInfo.path("preferred_username").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("nickname").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("name").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("email").takeIf { !it.isMissingNode && !it.isNull }?.asText()?.substringBefore("@")
            ?: userInfo.path("sub").takeIf { !it.isMissingNode && !it.isNull }?.asText()
    }

    /**
     * Generate random state for CSRF protection
     */
    private fun generateState(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..32).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
    }

    /**
     * Generate random secret for access token
     */
    private fun generateSecret(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..64).map { chars[secureRandom.nextInt(chars.length)] }.joinToString("")
    }

    /**
     * Response DTO for OIDC configuration
     */
    data class OidcConfigurationResponse(
        val enabled: Boolean,
        val issuer: String?,
        val useDiscovery: Boolean,
        val authorizationEndpoint: String,
        val tokenEndpoint: String,
        val userInfoEndpoint: String,
        val jwksUri: String
    )

    /**
     * OIDC Discovery Document
     */
    data class DiscoveryDocument(
        val authorizationEndpoint: String,
        val tokenEndpoint: String,
        val userInfoEndpoint: String,
        val jwksUri: String,
        val issuer: String
    )

    /**
     * Token response from OIDC Provider
     */
    private data class TokenResponse(
        val accessToken: String,
        val idToken: String?,
        val tokenType: String,
        val expiresIn: Int
    )
}
