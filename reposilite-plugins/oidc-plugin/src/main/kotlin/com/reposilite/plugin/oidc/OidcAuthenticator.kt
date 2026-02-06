/*
 * Copyright (c) 2026 cnlimiter
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
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTDecodeException
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.reposilite.auth.Authenticator
import com.reposilite.auth.api.Credentials
import com.reposilite.journalist.Journalist
import com.reposilite.shared.ErrorResponse
import com.reposilite.shared.badRequestError
import com.reposilite.shared.unauthorizedError
import com.reposilite.token.AccessTokenFacade
import com.reposilite.token.api.AccessTokenDto
import com.reposilite.token.api.CreateAccessTokenRequest
import panda.std.Result
import panda.std.asSuccess
import panda.std.reactive.MutableReference
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * OIDC Authenticator that handles Bearer Token authentication using ID Tokens.
 *
 * This authenticator validates JWT tokens from the configured OIDC provider
 * and creates access tokens for authenticated users.
 */
class OidcAuthenticator(
    private val journalist: Journalist,
    private val oidcSettings: MutableReference<OidcSettings>,
    private val accessTokenFacade: AccessTokenFacade,
    private val oidcFacade: OidcFacade
) : Authenticator {

    override fun authenticate(credentials: Credentials): Result<AccessTokenDto, ErrorResponse> {
        val settings = oidcSettings.get()

        if (!settings.enabled) {
            return unauthorizedError("OIDC authentication is disabled")
        }

        // Extract Bearer token from credentials.secret (Authorization header value)
        val bearerToken = credentials.secret
        if (!bearerToken.startsWith(settings.tokenType, ignoreCase = true)) {
            return badRequestError("Invalid authorization header format. Expected: Bearer <token>")
        }

        val token = bearerToken.substringAfter(" ").trim()
        if (token.isBlank()) {
            return badRequestError("Empty authorization token")
        }

        return validateToken(token, credentials.name)
    }

    private fun validateToken(token: String, host: String): Result<AccessTokenDto, ErrorResponse> {
        val settings = oidcSettings.get()

        try {
            // Decode JWT without verification first to get claims
            val decodedJWT = try {
                JWT.decode(token)
            } catch (e: JWTDecodeException) {
                return unauthorizedError("Invalid JWT token format: ${e.message}")
            }

            // Validate issuer if configured
            if (settings.verifyIssuer && decodedJWT.issuer != settings.issuer) {
                return unauthorizedError("Token issuer mismatch. Expected: ${settings.issuer}, got: ${decodedJWT.issuer}")
            }

            // Validate audience if configured
            if (!decodedJWT.audience.contains(settings.clientId)) {
                return unauthorizedError("Token audience mismatch. Expected: ${settings.clientId}")
            }

            // Validate expiration
            if (decodedJWT.expiresAt != null && decodedJWT.expiresAt.before(java.util.Date())) {
                return unauthorizedError("Token has expired")
            }

            // Validate not before
            if (decodedJWT.notBefore != null && decodedJWT.notBefore.after(java.util.Date())) {
                return unauthorizedError("Token is not yet valid")
            }

            // Get user identifier from configured claim
            val userId = decodedJWT.getClaim(settings.userIdClaim).asString()
            val username = decodedJWT.getClaim(settings.usernameClaim).asString()

            if (userId.isNullOrBlank()) {
                return unauthorizedError("Token does not contain valid user identifier in claim: ${settings.userIdClaim}")
            }

            // Determine the token name (use username if available, otherwise userId)
            val tokenName = username ?: userId

            // Check if access token already exists, create if needed
            val accessTokenDto = accessTokenFacade.getAccessToken(tokenName)
                ?: if (settings.autoCreateUsers) {
                    val response = accessTokenFacade.createAccessToken(
                        CreateAccessTokenRequest(
                            type = com.reposilite.token.AccessTokenType.PERSISTENT,
                            name = tokenName,
                            secret = token // Use the OIDC token as the secret
                        )
                    )
                    journalist.logger.debug("[OIDC] Auto-created access token for user: $tokenName")
                    response.accessToken
                } else {
                    return unauthorizedError("User $tokenName not found. Auto-create is disabled.")
                }

            return accessTokenDto.asSuccess()

        } catch (e: JWTVerificationException) {
            journalist.logger.debug("[OIDC] Token verification failed: ${e.message}")
            return unauthorizedError("Token verification failed: ${e.message}")
        } catch (e: Exception) {
            journalist.logger.debug("[OIDC] Token validation error: ${e.message}")
            return unauthorizedError("Token validation error: ${e.message}")
        }
    }

    override fun enabled(): Boolean =
        oidcSettings.map { it.enabled }

    override fun priority(): Double =
        2.0 // Higher than Basic (0.0) and LDAP (-1.0)

    override fun realm(): String =
        "OIDC"
}
