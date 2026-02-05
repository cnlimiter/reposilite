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

import { reactive, watch } from 'vue'

// Translation dictionaries
const translations = {
  en: {
    // Navigation
    overview: 'Overview',
    dashboard: 'Dashboard',
    console: 'Console',
    settings: 'Settings',
    signIn: 'Sign in',
    logout: 'Logout',
    welcome: 'Welcome',

    // Common
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
    search: 'Search',
    loading: 'Loading...',
    error: 'Error',
    success: 'Success',
    confirm: 'Confirm',
    yes: 'Yes',
    no: 'No',

    // Settings
    general: 'General',
    security: 'Security',
    tokens: 'Access Tokens',
    statistics: 'Statistics',
    documentation: 'Documentation',

    // Dashboard
    requests: 'Requests',
    views: 'Views',
    size: 'Size',
    latest: 'Latest',
    deployedArtifacts: 'Deployed artifacts',

    // Console
    command: 'Command',
    send: 'Send',
    clear: 'Clear',

    // Browser
    browse: 'Browse',
    upload: 'Upload',
    download: 'Download',
    repository: 'Repository',
    group: 'Group',
    artifact: 'Artifact',
    version: 'Version',

    // Languages
    language: 'Language',
    english: 'English',
    chinese: 'Chinese',
    auto: 'Auto'
  },
  zh: {
    // Navigation
    overview: '概览',
    dashboard: '仪表盘',
    console: '控制台',
    settings: '设置',
    signIn: '登录',
    logout: '退出',
    welcome: '欢迎',

    // Common
    save: '保存',
    cancel: '取消',
    delete: '删除',
    edit: '编辑',
    search: '搜索',
    loading: '加载中...',
    error: '错误',
    success: '成功',
    confirm: '确认',
    yes: '是',
    no: '否',

    // Settings
    general: '常规',
    security: '安全',
    tokens: '访问令牌',
    statistics: '统计',
    documentation: '文档',

    // Dashboard
    requests: '请求',
    views: '视图',
    size: '大小',
    latest: '最新',
    deployedArtifacts: '已部署构件',

    // Console
    command: '命令',
    send: '发送',
    clear: '清除',

    // Browser
    browse: '浏览',
    upload: '上传',
    download: '下载',
    repository: '仓库',
    group: '分组',
    artifact: '构件',
    version: '版本',

    // Languages
    language: '语言',
    english: 'English',
    chinese: '中文',
    auto: '自动'
  }
}

// Language state
const languageState = reactive({
  locale: 'en',
  fallbackLocale: 'en'
})

const languageKey = 'reposilite-language'

// Get available translations for a key
const t = (key) => {
  const keys = key.split('.')
  let result = translations[languageState.locale]

  for (const k of keys) {
    result = result?.[k]
    if (result === undefined) break
  }

  // Fallback to English
  if (result === undefined) {
    result = translations['en']
    for (const k of keys) {
      result = result?.[k]
      if (result === undefined) break
    }
  }

  return result ?? key
}

export default function useI18n() {
  // Initialize language from localStorage or browser preference
  const initLanguage = () => {
    const storedLang = localStorage.getItem(languageKey)

    if (storedLang && translations[storedLang]) {
      languageState.locale = storedLang
    } else {
      // Try to detect browser language
      const browserLang = navigator.language?.split('-')[0] || 'en'
      if (translations[browserLang]) {
        languageState.locale = browserLang
      } else {
        languageState.locale = 'en'
      }
    }

    localStorage.setItem(languageKey, languageState.locale)
    document.documentElement.lang = languageState.locale
  }

  // Change language
  const setLocale = (locale) => {
    if (translations[locale]) {
      languageState.locale = locale
      localStorage.setItem(languageKey, locale)
      document.documentElement.lang = locale
    }
  }

  // Get current locale
  const getLocale = () => languageState.locale

  // Check if locale is Chinese
  const isChinese = () => languageState.locale === 'zh'

  return {
    locale: languageState,
    t,
    initLanguage,
    setLocale,
    getLocale,
    isChinese,
    availableLocales: ['en', 'zh']
  }
}
