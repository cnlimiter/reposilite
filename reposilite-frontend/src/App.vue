<!--
  - Copyright (c) 2023 dzikoysk
  -
  - Licensed under the Apache License, Version 2.0 (the "License");
  - you may not use this file except in compliance with the License.
  - You may obtain a copy of the License at
  -
  -     http://www.apache.org/licenses/LICENSE-2.0
  -
  - Unless required by applicable law or agreed to in writing, software
  - distributed under the License is distributed on an "AS IS" BASIS,
  - WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  - See the License for the specific language governing permissions and
  - limitations under the License.
  -->

<script setup>
import { useHead } from '@vueuse/head'
import { useSession } from "./store/session"
import useTheme from "./store/theme"
import useQualifier from "./store/qualifier"
import usePlaceholders from './store/placeholders'
import useLocale from "./store/locale"

const { title, description, icpLicense } = usePlaceholders()
const { theme, fetchColorMode } = useTheme()
const { initializeSession, setToken } = useSession()
const { qualifier } = useQualifier()
const { fetchLocale } = useLocale()

useHead({
  title,
  description
})

// 处理 OIDC 回调返回的 token 参数
const handleOidcCallback = () => {
  const urlParams = new URLSearchParams(window.location.search)
  const tokenName = urlParams.get('token_name')
  const tokenSecret = urlParams.get('token_secret')

  if (tokenName && tokenSecret) {
    // 保存到 localStorage
    localStorage.setItem('token-name', tokenName)
    localStorage.setItem('token-secret', tokenSecret)
    // 清理 URL 参数
    window.history.replaceState({}, document.title, window.location.pathname)
    return true
  }
  return false
}

fetchColorMode()
fetchLocale()
// OIDC 回调优先处理
if (!handleOidcCallback()) {
  initializeSession().catch(() => {})
}
</script>

<template>
  <div v-bind:class="{ 'dark': theme.isDark }">
    <div class="min-h-screen dark:bg-black dark:text-white">
      <router-view 
        class="router-view-full "
        :qualifier="qualifier"
      />
      <div v-if="icpLicense" class="absolute h-8 pb-2 w-full text-center text-xs dark:bg-black dark:text-white">
        <a href="https://beian.miit.gov.cn" target="_blank">{{ icpLicense }}</a>
      </div>
    </div>
  </div>
</template>

<style>
@import url('https://fonts.googleapis.com/css2?family=Open+Sans:wght@300;400;500;600&display=swap');

html, body {
  @apply bg-gray-100 dark:bg-black;
}
#app {
  font-family: 'Open Sans', sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
.router-view-full {
  min-height: calc(100vh - 2rem);
}
.container {
  @apply px-10 <sm:px-2;
}
.active {
  @apply dark:border-white;
}
.bg-default {
  @apply bg-gray-100 dark:border-gray-900;
}
</style>
