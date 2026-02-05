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

import com.reposilite.plugin.api.Facade

/**
 * Facade interface for OIDC plugin providing OIDC-related operations.
 */
interface OidcFacade : Facade {

    /**
     * Get the authorization URL to redirect users to the OIDC provider.
     */
    fun getAuthorizationUrl(): String

    /**
     * Handle the OAuth2 callback and exchange the authorization code for tokens.
     * @param code The authorization code from the OIDC provider
     * @return The OIDC user session
     */
    fun handleCallback(code: String): OidcUserSession

    /**
     * Get the current user's session information.
     * @param accessToken The access token to validate
     * @return The OIDC user session if valid, null otherwise
     */
    fun getCurrentSession(accessToken: String): OidcUserSession?

    /**
     * Generate a new authorization URL with a fresh state.
     */
    fun generateAuthorizationUrl(): String

    /**
     * Get the current OIDC settings.
     */
    fun getOidcSettings(): OidcSettings
}
