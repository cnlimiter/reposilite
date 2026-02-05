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

import com.reposilite.web.api.ReposiliteRoute
import com.reposilite.web.api.ReposiliteRoutes
import io.javalin.community.routing.Route
import io.javalin.openapi.*

/**
 * OIDC Endpoints for OAuth2 authentication flow.
 */
class OidcEndpoints(
    private val oidcFacade: OidcFacade
) : ReposiliteRoutes() {

    @OpenApi(
        path = "/api/auth/oidc/login",
        methods = [HttpMethod.GET],
        summary = "Initiate OIDC login",
        description = "Redirects the user to the OIDC provider for authentication",
        responses = [
            OpenApiResponse(status = "302", description = "Redirect to OIDC provider")
        ]
    )
    private val oidcLogin = ReposiliteRoute<Unit>("/api/auth/oidc/login", Route.GET) {
        val authorizationUrl = oidcFacade.generateAuthorizationUrl()
        ctx.redirect(authorizationUrl)
    }

    @OpenApi(
        path = "/api/auth/oidc/callback",
        methods = [HttpMethod.GET],
        summary = "OIDC callback handler",
        description = "Handles the OAuth2 callback from the OIDC provider",
        queryParams = [
            OpenApiParam(name = "code", description = "Authorization code"),
            OpenApiParam(name = "error", description = "Error code if authentication failed"),
            OpenApiParam(name = "error_description", description = "Error description")
        ],
        responses = [
            OpenApiResponse(
                status = "200",
                description = "Successful authentication response",
                content = [OpenApiContent(from = OidcCallbackResponse::class)]
            ),
            OpenApiResponse(
                status = "400",
                description = "Missing authorization code",
                content = [OpenApiContent(from = OidcErrorResponse::class)]
            ),
            OpenApiResponse(
                status = "401",
                description = "Authentication failed",
                content = [OpenApiContent(from = OidcErrorResponse::class)]
            )
        ]
    )
    private val oidcCallback = ReposiliteRoute<Unit>("/api/auth/oidc/callback", Route.GET) {
        val code = ctx.queryParam("code")
        val error = ctx.queryParam("error")
        val errorDescription = ctx.queryParam("error_description")

        if (error != null) {
            ctx.status(401).json(OidcErrorResponse(
                error = error,
                errorDescription = errorDescription ?: "Authentication failed"
            ))
            return@ReposiliteRoute
        }

        if (code == null) {
            ctx.status(400).json(OidcErrorResponse(
                error = "invalid_request",
                errorDescription = "Missing authorization code"
            ))
            return@ReposiliteRoute
        }

        try {
            val session = oidcFacade.handleCallback(code)
            ctx.json(OidcCallbackResponse(
                success = true,
                user = OidcUserResponse(
                    id = session.userId,
                    username = session.username,
                    email = session.email
                ),
                expiresAt = session.expiresAt
            ))
        } catch (e: Exception) {
            ctx.status(500).json(OidcErrorResponse(
                error = "authentication_failed",
                errorDescription = e.message ?: "Unknown error during authentication"
            ))
        }
    }

    @OpenApi(
        path = "/api/auth/oidc/user",
        methods = [HttpMethod.GET],
        summary = "Get current OIDC user",
        description = "Returns information about the currently authenticated OIDC user",
        headers = [
            OpenApiParam(name = "Authorization", description = "Bearer token", required = true)
        ],
        responses = [
            OpenApiResponse(
                status = "200",
                description = "Current user information",
                content = [OpenApiContent(from = OidcUserInfoResponse::class)]
            ),
            OpenApiResponse(
                status = "401",
                description = "Unauthorized - missing or invalid token",
                content = [OpenApiContent(from = OidcErrorResponse::class)]
            )
        ]
    )
    private val oidcUser = ReposiliteRoute<Unit>("/api/auth/oidc/user", Route.GET) {
        val authorizationHeader = ctx.header("Authorization")
        if (authorizationHeader == null) {
            ctx.status(401).json(OidcErrorResponse(
                error = "unauthorized",
                errorDescription = "Missing Authorization header"
            ))
            return@ReposiliteRoute
        }

        val session = oidcFacade.getCurrentSession(authorizationHeader)
        if (session == null) {
            ctx.status(401).json(OidcErrorResponse(
                error = "unauthorized",
                errorDescription = "Invalid or expired session"
            ))
            return@ReposiliteRoute
        }

        ctx.json(OidcUserInfoResponse(
            id = session.userId,
            username = session.username,
            email = session.email,
            expiresAt = session.expiresAt
        ))
    }

    @OpenApi(
        path = "/api/auth/oidc/configuration",
        methods = [HttpMethod.GET],
        summary = "Get OIDC configuration",
        description = "Returns the OIDC provider configuration",
        responses = [
            OpenApiResponse(
                status = "200",
                description = "OIDC configuration",
                content = [OpenApiContent(from = OidcConfigurationResponse::class)]
            )
        ]
    )
    private val oidcConfiguration = ReposiliteRoute<Unit>("/api/auth/oidc/configuration", Route.GET) {
        val settings = oidcFacade.getOidcSettings()
        ctx.json(OidcConfigurationResponse(
            issuer = settings.issuer,
            clientId = settings.clientId,
            redirectUri = settings.redirectUri,
            scopes = settings.scopes.split(" ").filter { it.isNotBlank() },
            tokenType = settings.tokenType
        ))
    }

    override val routes = routes(oidcLogin, oidcCallback, oidcUser, oidcConfiguration)
}

data class OidcCallbackResponse(
    val success: Boolean,
    val user: OidcUserResponse,
    val expiresAt: Long
)

data class OidcUserResponse(
    val id: String,
    val username: String,
    val email: String?
)

data class OidcUserInfoResponse(
    val id: String,
    val username: String,
    val email: String?,
    val expiresAt: Long
)

data class OidcErrorResponse(
    val error: String,
    val errorDescription: String
)

data class OidcConfigurationResponse(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scopes: List<String>,
    val tokenType: String
)
