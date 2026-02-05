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

import com.reposilite.auth.AuthenticationFacade
import com.reposilite.configuration.shared.SharedConfigurationFacade
import com.reposilite.plugin.api.Facade
import com.reposilite.plugin.api.Plugin
import com.reposilite.plugin.api.ReposilitePlugin
import com.reposilite.plugin.event
import com.reposilite.plugin.facade
import com.reposilite.web.api.RoutingSetupEvent

/**
 * OIDC Plugin for Reposilite
 *
 * Provides OpenID Connect (OIDC) authentication support with:
 * - OAuth2 authorization code flow with user redirection
 * - Bearer Token authentication (Authorization header)
 * - Integration with existing Reposilite authentication system
 *
 * Supports Keycloak, Auth0, Okta, Google Identity Platform and other OIDC providers.
 */
@Plugin(
    name = "oidc",
    dependencies = ["shared-configuration", "authentication", "access-token"],
    settings = OidcSettings::class
)
class OidcPlugin : ReposilitePlugin() {

    override fun initialize(): Facade? {
        // Get shared configuration facade to access OIDC settings
        val sharedConfigurationFacade = facade<SharedConfigurationFacade>()
        val oidcSettings = sharedConfigurationFacade.getDomainSettings<OidcSettings>()

        // Get access token facade for auto-creating users
        val accessTokenFacade = facade<com.reposilite.token.AccessTokenFacade>()

        // Create OIDC facade implementation
        val oidcFacade = OidcFacadeImpl(
            journalist = this,
            oidcSettings = oidcSettings,
            accessTokenFacade = accessTokenFacade
        )

        // Register routes for OAuth2 endpoints
        event { event: RoutingSetupEvent ->
            event.registerRoutes(OidcEndpoints(oidcFacade))
        }

        // Register OIDC authenticator with authentication facade
        val authenticationFacade = facade<AuthenticationFacade>()
        authenticationFacade.registerAuthenticator(oidcFacade.createAuthenticator())

        return oidcFacade
    }
}
