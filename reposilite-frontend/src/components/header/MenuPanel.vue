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
import { ref, onMounted, onUnmounted } from 'vue'
import { useSession } from '../../store/session'
import MenuButton from './MenuButton.vue'
import LoginModal from './LoginModal.vue'
import MoonIcon from '../icons/MoonIcon.vue'
import SunIcon from '../icons/SunIcon.vue'
import LogoutIcon from '../icons/LogoutIcon.vue'
import LanguageIcon from '../icons/LanguageIcon.vue'
import useTheme from "../../store/theme"
import useLocale from "../../store/locale"

const { theme, changeTheme } = useTheme()
const { locale, changeLocale } = useLocale()
const { token, isLogged, logout } = useSession()
const showLocaleDropdown = ref(false)
const localeDropdownRef = ref(null)

const toggleTheme = () => {
  switch (theme.mode) {
    case 'light':
      changeTheme('dark')
      break
    case 'dark':
      changeTheme('auto')
      break
    case 'auto':
      changeTheme('light')
      break
  }
}

const toggleLocaleDropdown = () => {
  showLocaleDropdown.value = !showLocaleDropdown.value
}

const selectLocale = (code) => {
  changeLocale(code)
  showLocaleDropdown.value = false
}

const closeLocaleDropdown = (event) => {
  if (localeDropdownRef.value && !localeDropdownRef.value.contains(event.target)) {
    showLocaleDropdown.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', closeLocaleDropdown)
})

onUnmounted(() => {
  document.removeEventListener('click', closeLocaleDropdown)
})
</script>

<template>
  <nav class="flex flex-row items-center <sm:(max-w-100px flex-wrap flex-1 justify-end min-w-1/2) relative">
    <div v-if="isLogged" class="pt-1.1 px-2 <sm:hidden">
      {{ $t('welcome') }}
      <span class="font-bold underline">{{ token.name }}</span>
    </div>
    <LoginModal>
      <template v-slot:button>
        <MenuButton v-if="!isLogged">
          {{ $t('signIn') }}
        </MenuButton>
      </template>
    </LoginModal>
    <MenuButton v-if="isLogged" @click="logout()" class="<sm:hidden">
      {{ $t('logout') }}
    </MenuButton>
    <div
      v-if="isLogged"
      class="hidden px-2.7 pt-0.8 mr-1.5 cursor-pointer rounded-full bg-white dark:bg-gray-900 max-h-35px <sm:(block pt-1.5)"
    >
      <LogoutIcon @click="logout()"/>
    </div>
    <!-- Language Dropdown -->
    <div ref="localeDropdownRef" class="relative">
      <div
        class="flex justify-center items-center rounded-full w-40px h-35px default-button cursor-pointer"
        @click="toggleLocaleDropdown()"
      >
        <LanguageIcon />
      </div>
      <div
        v-if="showLocaleDropdown"
        class="absolute right-0 mt-2 py-2 w-48 bg-white dark:bg-gray-900 rounded-lg shadow-xl z-50 border border-gray-200 dark:border-gray-700"
      >
        <button
          v-for="lang in locale.available"
          :key="lang.code"
          @click="selectLocale(lang.code)"
          class="w-full px-4 py-2 text-left hover:bg-gray-100 dark:hover:bg-gray-800 flex items-center gap-2"
          :class="{ 'text-blue-600 dark:text-blue-400 font-bold': locale.current === lang.code }"
        >
          <span>{{ lang.flag }}</span>
          <span>{{ lang.name }}</span>
          <span v-if="locale.current === lang.code" class="ml-auto">✓</span>
        </button>
      </div>
    </div>
    <!-- Theme Toggle -->
    <div class="flex justify-center items-center rounded-full w-40px h-35px default-button" @click="toggleTheme()">
      <SunIcon v-if="theme.mode === 'light'"/>
      <MoonIcon class="pl-0.5" v-if="theme.mode === 'dark'"/>
      <div class="font-bold w-full text-center text-lg" v-if="theme.mode === 'auto'">
        A
      </div>
    </div>
  </nav>
</template>
