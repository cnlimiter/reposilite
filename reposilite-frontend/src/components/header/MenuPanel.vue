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
import { ref, computed } from 'vue'
import { useSession } from '../../store/session'
import MenuButton from './MenuButton.vue'
import LoginModal from './LoginModal.vue'
import MoonIcon from '../icons/MoonIcon.vue'
import SunIcon from '../icons/SunIcon.vue'
import LogoutIcon from '../icons/LogoutIcon.vue'
import LanguageIcon from '../icons/LanguageIcon.vue'
import useTheme from "../../store/theme"
import useI18n from "../../store/i18n"

const { theme, changeTheme } = useTheme()
const { t, setLocale, getLocale, isChinese } = useI18n()
const { token, isLogged, logout } = useSession()

const showLanguageMenu = ref(false)

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

const currentLanguageLabel = computed(() => {
  const locale = getLocale()
  return locale === 'zh' ? '中文' : 'EN'
})

const toggleLanguage = () => {
  const newLocale = isChinese() ? 'en' : 'zh'
  setLocale(newLocale)
  showLanguageMenu.value = false
}

const languages = [
  { code: 'en', label: 'English' },
  { code: 'zh', label: '中文' }
]
</script>

<template>
  <nav class="flex flex-row <sm:(max-w-100px flex-wrap flex-1 justify-end min-w-1/2)">
    <div v-if="isLogged" class="pt-1.1 px-2 <sm:hidden">
      {{ t('welcome') }}
      <span class="font-bold underline">{{ token.name }}</span>
    </div>
    <LoginModal>
      <template v-slot:button>
        <MenuButton v-if="!isLogged">
          {{ t('signIn') }}
        </MenuButton>
      </template>
    </LoginModal>
    <MenuButton v-if="isLogged" @click="logout()" class="<sm:hidden">
      {{ t('logout') }}
    </MenuButton>
    <div
      v-if="isLogged"
      class="hidden px-2.7 pt-0.8 mr-1.5 cursor-pointer rounded-full bg-white dark:bg-gray-900 max-h-35px <sm:(block pt-1.5)"
    >
      <LogoutIcon @click="logout()"/>
    </div>

    <!-- Language Switcher -->
    <div class="relative">
      <div
        class="flex justify-center items-center rounded-full w-40px h-35px default-button cursor-pointer"
        @click="showLanguageMenu = !showLanguageMenu"
        :title="t('language')"
      >
        <LanguageIcon />
      </div>

      <!-- Language Dropdown -->
      <div
        v-if="showLanguageMenu"
        class="absolute right-0 mt-2 w-32 bg-white dark:bg-gray-900 rounded-lg shadow-lg py-1 z-50 border dark:border-gray-700"
      >
        <button
          v-for="lang in languages"
          :key="lang.code"
          @click="setLocale(lang.code); showLanguageMenu = false"
          class="block w-full text-left px-4 py-2 text-sm hover:bg-gray-100 dark:hover:bg-gray-800"
          :class="{ 'font-bold bg-gray-50 dark:bg-gray-800': getLocale() === lang.code }"
        >
          {{ lang.label }}
        </button>
      </div>
    </div>

    <!-- Theme Switcher -->
    <div class="flex justify-center items-center rounded-full w-40px h-35px default-button ml-1" @click="toggleTheme()">
      <SunIcon v-if="theme.mode === 'light'"/>
      <MoonIcon class="pl-0.5" v-if="theme.mode === 'dark'"/>
      <div class="font-bold w-full text-center text-lg" v-if="theme.mode === 'auto'">
        A
      </div>
    </div>
  </nav>
</template>
