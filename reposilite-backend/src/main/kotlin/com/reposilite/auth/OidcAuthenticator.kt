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

package com.reposilite.auth

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.reposilite.auth.api.Credentials
import com.reposilite.auth.application.OidcSettings
import com.reposilite.journalist.Journalist
import com.reposilite.shared.ErrorResponse
import com.reposilite.shared.badRequestError
import com.reposilite.status.FailureFacade
import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.api.AccessTokenDto
import com.reposilite.token.api.CreateAccessTokenRequest
import okhttp3.OkHttpClient
import okhttp3.Request
import panda.std.Result
import panda.std.asSuccess
import panda.std.reactive.Reference
import java.io.IOException
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * OIDC Authenticator - Handles OpenID Connect authentication
 */
internal class OidcAuthenticator(
    private val journalist: Journalist,
    private val oidcSettings: Reference<OidcSettings>,
    private val accessTokenFacade: AccessTokenFacade,
    private val failureFacade: FailureFacade,
    private val httpClient: OkHttpClient
) : Authenticator {

    private val objectMapper = ObjectMapper()

    override fun authenticate(credentials: Credentials): Result<AccessTokenDto, ErrorResponse> =
        with(oidcSettings.get()) {
            // 1. Parse ID Token
            parseIdToken(credentials.secret)
                // 2. Validate Token (issuer, audience, expiration)
                .flatMap { validateToken(it) }
                // 3. Get UserInfo
                .flatMap { jwt -> fetchUserInfo(jwt).map { jwt to it } }
                // 4. Extract username
                .flatMap { (_, userInfo) -> extractUsername(userInfo) }
                // 5. Create/Access AccessToken
                .flatMap { username ->
                    accessTokenFacade.getAccessToken(username)
                        ?.asSuccess()
                        ?: createAccessToken(username)
                }
        }

    /**
     * Parse JWT token string to SignedJWT
     */
    private fun parseIdToken(token: String): Result<SignedJWT, ErrorResponse> =
        try {
            SignedJWT.parse(token).asSuccess()
        } catch (e: JOSEException) {
            journalist.logger.debug("[OIDC] Failed to parse ID token: ${e.message}")
            badRequestError("Invalid token format")
        }

    /**
     * Validate JWT token (issuer, audience, expiration)
     */
    private fun validateToken(jwt: SignedJWT): Result<SignedJWT, ErrorResponse> {
        val claims = jwt.jwtClaimsSet
        val settings = oidcSettings.get()

        // Validate issuer
        if (claims.issuer != settings.issuer) {
            journalist.logger.debug("[OIDC] Issuer mismatch: expected=${settings.issuer}, actual=${claims.issuer}")
            return badRequestError("Invalid token issuer")
        }

        // Validate audience (client ID)
        val audience = claims.audience
        if (audience == null || !audience.contains(settings.clientId)) {
            journalist.logger.debug("[OIDC] Audience mismatch: expected=${settings.clientId}, actual=$audience")
            return badRequestError("Invalid token audience")
        }

        // Validate expiration
        val expirationTime = claims.expirationTime
        if (expirationTime != null && expirationTime.before(Date())) {
            journalist.logger.debug("[OIDC] Token expired at $expirationTime")
            return badRequestError("Token has expired")
        }

        // Validate signature
        if (!verifySignature(jwt)) {
            journalist.logger.debug("[OIDC] Token signature verification failed")
            return badRequestError("Invalid token signature")
        }

        return jwt.asSuccess()
    }

    /**
     * Verify JWT signature using OIDC Provider's JWKS
     */
    private fun verifySignature(jwt: SignedJWT): Boolean {
        val settings = oidcSettings.get()
        // Use configured JWKS URI, or fallback to Keycloak default path
        val jwksUrl = settings.jwksUri.ifBlank {
            "${settings.issuer}/protocol/openid-connect/certs"
        }

        return try {
            val jwkSet = fetchJWKSet(jwksUrl)
            if (jwkSet == null) {
                journalist.logger.warn("[OIDC] Failed to fetch JWKS from $jwksUrl")
                return false
            }

            // Try to find key by key ID first, then fall back to any RSA key
            val keyID = jwt.header.keyID
            val jwk = if (keyID != null) {
                jwkSet.getKeyByKeyId(keyID)
            } else {
                null
            } ?: jwkSet.keys.firstOrNull { it.keyUse == KeyUse.SIGNATURE || it is RSAKey }

            if (jwk !is RSAKey) {
                journalist.logger.warn("[OIDC] No suitable RSA key found in JWKS")
                return false
            }

            val verifier = RSASSAVerifier(jwk.toRSAPublicKey())
            jwt.verify(verifier)
        } catch (e: Exception) {
            journalist.logger.debug("[OIDC] Signature verification error: ${e.message}")
            false
        }
    }

    /**
     * Fetch JWK Set from OIDC Provider
     */
    private fun fetchJWKSet(jwksUrl: String): JWKSet? {
        val request = Request.Builder()
            .url(jwksUrl)
            .get()
            .build()

        return try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    journalist.logger.debug("[OIDC] Failed to fetch JWKS: HTTP ${response.code}")
                    return null
                }
                val body = response.body?.string() ?: return null
                JWKSet.parse(body)
            }
        } catch (e: IOException) {
            journalist.logger.debug("[OIDC] Failed to fetch JWKS: ${e.message}")
            null
        }
    }

    /**
     * Fetch UserInfo from OIDC Provider
     */
    private fun fetchUserInfo(jwt: SignedJWT): Result<JsonNode, ErrorResponse> {
        val settings = oidcSettings.get()
        // Use configured UserInfo endpoint, or fallback to Keycloak default path
        val userInfoUrl = settings.userInfoEndpoint.ifBlank {
            "${settings.issuer}/protocol/openid-connect/userinfo"
        }
        val accessToken = jwt.jwtClaimsSet.getStringClaim("access_token")

        val request = Request.Builder()
            .url(userInfoUrl)
            .addHeader("Authorization", "Bearer $accessToken")
            .get()
            .build()

        return try {
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    journalist.logger.debug("[OIDC] Failed to fetch UserInfo: HTTP ${response.code}")
                    return badRequestError("Failed to fetch user info")
                }
                val body = response.body?.string() ?: return badRequestError("Empty user info response")
                objectMapper.readTree(body).asSuccess()
            }
        } catch (e: IOException) {
            journalist.logger.debug("[OIDC] UserInfo fetch error: ${e.message}")
            badRequestError("Failed to fetch user info")
        }
    }

    /**
     * Extract username from UserInfo response
     */
    private fun extractUsername(userInfo: JsonNode): Result<String, ErrorResponse> {
        // Try common username fields in order of preference
        val username = userInfo.path("preferred_username").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("nickname").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("name").takeIf { !it.isMissingNode && !it.isNull }?.asText()
            ?: userInfo.path("email").takeIf { !it.isMissingNode && !it.isNull }?.asText()?.substringBefore("@")
            ?: userInfo.path("sub").textValue()

        return if (username.isNullOrBlank()) {
            journalist.logger.debug("[OIDC] No username found in UserInfo")
            badRequestError("Could not extract username from user info")
        } else {
            journalist.logger.debug("[OIDC] Extracted username: $username")
            username.asSuccess()
        }
    }

    /**
     * Create new AccessToken for OIDC user
     */
    private fun createAccessToken(username: String): Result<AccessTokenDto, ErrorResponse> =
        try {
            val settings = oidcSettings.get()
            journalist.logger.debug("[OIDC] Creating access token for user: $username")

            accessTokenFacade.createAccessToken(
                CreateAccessTokenRequest(
                    type = settings.tokenType,
                    name = username,
                    secret = generateSecret()
                )
            ).accessToken.asSuccess()
        } catch (e: Exception) {
            journalist.logger.debug("[OIDC] Failed to create access token: ${e.message}")
            badRequestError("Failed to create access token")
        }

    /**
     * Generate a random secret for the access token
     */
    private fun generateSecret(): String {
        val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return (1..64).map { chars.random() }.joinToString("")
    }

    override fun enabled(): Boolean = oidcSettings.map { it.enabled }

    override fun priority(): Double = -0.5

    override fun realm(): String = "OIDC"

    companion object {
        fun createHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()
    }
}
