package com.fadlurahmanfdev.mark_authenticator.base

import javax.crypto.Cipher
import javax.crypto.SecretKey

interface BaseMarkAuthenticatorUtils {
    fun cipher(): Cipher
    fun getSecretKey(alias: String): SecretKey?
}