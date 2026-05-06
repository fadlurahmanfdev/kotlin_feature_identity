package com.fadlurahmanfdev.mark_authenticator

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.mark_authenticator.base.BaseMarkAuthenticatorUtils
import com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object MarkAuthenticatorUtils : BaseMarkAuthenticatorUtils {
    override fun cipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
    override fun getSecretKey(alias: String): SecretKey? {
        var secretKey: SecretKey? = null
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            secretKey = keyStore.getKey(alias, null) as SecretKey?
        } catch (e: Throwable) {
            Log.wtf(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% failed to get secret key caused by ${e.toString()}"
            )
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_FETCH_GET_SECRET_KEY,
                message = e.message,
                cause = e,
            )
        }

        return secretKey
    }

    fun generateSecretKey(alias: String): SecretKey {
        var secretKey: SecretKey? = getSecretKey(alias)

        if (secretKey != null) {
            Log.i(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% secret key for specific alias is already exist"
            )
            throw MarkAuthenticatorException(
                code = ErrorConstant.SECRET_KEY_ALREADY_EXIST,
                message = "Secret Key Already Exist"
            );
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(generateKeyGenParameterSpec(alias))
            secretKey = keyGenerator.generateKey()
        } else {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256)
            secretKey = keyGenerator.generateKey()
        }

        return secretKey
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKeyGenParameterSpec(alias: String): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(true)
            }
        }.build()
    }
}