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

import { reactive } from 'vue'

const oidc = reactive({
  enabled: false,
  loading: true
})

export default function useOidc() {
  const fetchOidcStatus = async () => {
    oidc.loading = true
    try {
      const response = await fetch('/api/auth/oidc/configuration')
      oidc.enabled = response.ok
    } catch {
      oidc.enabled = false
    } finally {
      oidc.loading = false
    }
  }

  const login = () => {
    window.location.href = '/api/auth/oidc/login'
  }

  return {
    oidc,
    fetchOidcStatus,
    login
  }
}
