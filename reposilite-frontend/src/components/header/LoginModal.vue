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
import {onMounted, ref} from 'vue'
import {VueFinalModal} from 'vue-final-modal'
import {createToast} from 'mosha-vue-toastify'
import {useSession} from '../../store/session'
import CloseIcon from '../icons/CloseIcon.vue'
import useLocale from '../../store/locale'
import {createClient} from '../../store/client'

const { t } = useLocale()
const { login } = useSession()
const client = createClient()

const showLogin = ref(false)
const name = ref('')
const secret = ref('')
const oidcEnabled = ref(false)

const close = () =>
  (showLogin.value = false)

const signin = (name, secret) =>
  login(name, secret)
    .then(() => createToast(t('dashboardAccessedAs') + ' ' + name, { position: 'bottom-right' }))
    .then(() => close())
    .catch(error => createToast(`${error.response?.status}: ${error.response?.data?.message}`, { type: 'danger' }))

const oidcLogin = () => {
  client.oidc.login()
}

const checkOidcEnabled = async () => {
  try {
    oidcEnabled.value = await client.oidc.isEnabled()
  } catch (e) {
    oidcEnabled.value = false
  }
}

onMounted(() => {
  checkOidcEnabled()
})
</script>

<script>
export default {
  inheritAttrs: false
}
</script>

<template>
  <div id="login-modal">
    <VueFinalModal
      v-model="showLogin"
      v-bind="$attrs"
      class="flex justify-center items-center"
      @click.self="close"
    >
      <div class="relative border bg-white dark:bg-gray-900 border-gray-100 dark:border-black m-w-20 py-5 px-10 rounded-2xl shadow-xl text-center">
        <p class="font-bold text-xl pb-4">{{ $t('loginWithToken') }}</p>
        <form class="flex flex-col w-96 <sm:w-65" @submit.prevent="signin(name, secret)">
          <input :placeholder="$t('name')" v-model="name" type="text" class="input"/>
          <input :placeholder="$t('secret')" v-model="secret" type="password" class="input"/>
          <button class="bg-gray-100 dark:bg-gray-800 py-2 my-3 rounded-md cursor-pointer">{{ $t('signIn') }}</button>
          <!-- OIDC 登录按钮 -->
          <div v-if="oidcEnabled" class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
            <button
                class="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md cursor-pointer w-full transition-colors"
                @click="oidcLogin"
            >
              {{ $t('loginWithOidc') || 'Login with OIDC' }}
            </button>
          </div>
        </form>
        <button class="absolute top-0 right-0 mt-5 mr-5" @click="close()">
          <CloseIcon />
        </button>
      </div>
    </VueFinalModal>
    <div @click="showLogin = true">
      <slot name="button"></slot>
    </div>
  </div>
</template>

<style scoped>
.input {
  @apply p-2;
  @apply my-1;
  @apply bg-gray-50 dark:bg-gray-800;
  @apply rounded-md;
}
#login-modal button:hover {
  @apply bg-gray-200 dark:bg-gray-700;
  transition: background-color 0.5s;
}
</style>
