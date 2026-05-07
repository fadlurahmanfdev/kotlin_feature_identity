package com.fadlurahmanfdev.mark_authenticator.base

import android.app.KeyguardManager
import android.hardware.biometrics.BiometricManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.core.callback.WeakAuthenticationCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticatorMethod
import com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

abstract class BaseMarkAuthenticator {
    lateinit var fingerprintManager: FingerprintManager
    lateinit var biometricManager: BiometricManager
    lateinit var keyguardManager: KeyguardManager

    /**
     * Cipher used for secure authentication
     *
     * the possible option is AES/GCM/NoPadding (recommended) & AES/CBC/PKCS7Padding
     * */
    abstract fun cipher(): Cipher

    fun getSecretKey(alias: String): SecretKey? {
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

    /**
     * Generate Secret Key for later used in secure biometric authentication
     *
     * @param alias Key Identifier
     * */
    abstract fun generateSecretKey(alias: String): SecretKey

    /**
     * Deletes an existing key from the Android KeyStore.
     *
     * @param alias The alias of the entry to delete from the KeyStore. Must not be empty.
     *
     * @throws MarkAuthenticatorException if unable to delete the key, with error code [ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY].
     */
    fun deleteSecretKey(alias: String){
        val secretKey = getSecretKey(alias)

        if (secretKey == null) {
            Log.i(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% secret key is not exist with specific alias"
            )
            return
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            keyStore.deleteEntry(alias)
            Log.i(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% successfully delete key with specific alias"
            )
        } catch (e: Throwable) {
            Log.e(
                this::class.java.simpleName,
                "failed to delete secret key $alias"
            )
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY,
                message = e.message,
                cause = e
            )
        }
    }

    /**
     * Checks if the device supports fingerprint authentication.
     *
     * @return true if the device supports fingerprint authentication; false otherwise.
     */
    abstract fun isDeviceSupportFingerprint(): Boolean

    /**
     * Checks if the device supports face authentication.
     *
     * @return true if the device supports face authentication; false otherwise.
     */
    abstract fun isDeviceSupportFaceAuth(): Boolean

    /**
     * Checks if the device supports biometric authentication, either fingerprint or face authentication.
     *
     * @return true if the device supports any biometric feature; false otherwise.
     */
    abstract fun isDeviceSupportBiometric(): Boolean

    /**
     * Checks if the device has at least one biometric enrolled.
     *
     * @return true if a biometric is enrolled; false otherwise.
     */
    abstract fun isBiometricEnrolled(): Boolean

    /**
     * Determines the device's credential is enrolled (PIN, Password, etc)
     *
     * @return true, if device's credential already enrolled, otherwise is false.
     */
    abstract fun isDeviceCredentialEnrolled(): Boolean

    /**
     * Checks the status of the specified authenticator.
     *
     * @param method The type of authenticator (biometric or device credential).
     *
     * @return [MarkAuthenticationStatus.SUCCESS] if the device can authenticate using the specified authenticator;
     * [MarkAuthenticationStatus.NONE_ENROLLED] if the device has no enrolled data for the specified authenticator;
     * [MarkAuthenticationStatus.NO_HARDWARE] if the device lacks the hardware for the specified authenticator;
     * [MarkAuthenticationStatus.UNAVAILABLE] if the device is currently unable to authenticate with the specified authenticator;
     * [MarkAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for the device to authenticate;
     * [MarkAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support authentication;
     * [MarkAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    abstract fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus

    /**
     * Checks the status of secure authentication on the device.
     *
     * @return [MarkAuthenticationStatus.SUCCESS] if the device can authenticate securely;
     * [MarkAuthenticationStatus.NO_HARDWARE] if the device lacks hardware for secure authentication;
     * [MarkAuthenticationStatus.UNAVAILABLE] if secure authentication is currently unavailable;
     * [MarkAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for secure authentication;
     * [MarkAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support secure authentication;
     * [MarkAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    abstract fun checkSecureAuthentication(): MarkAuthenticationStatus

    /**
     * Determines whether the device can authenticate using the specified authenticator.
     *
     * @param method The method of authenticator (biometric or device credential).
     *
     * @return true if the device can authenticate using the specified authenticator; false otherwise.
     */
    abstract fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean

    /**
     * Authenticate using device credentials.
     *
     * @param title The title displayed in the device credential prompt.
     * @param subTitle The sub-title displayed in the device credential prompt.
     * @param description The description shown in the device credential prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required for authentication.
     * @param callBack The callback to handle the authentication results:
     *
     * - **onSuccessAuthenticate**: Called when the authentication is successful, indicating that
     *   the user has correctly authenticated using their device credentials.
     *
     * - **onFailedAuthenticate**: Called when the authentication fails, usually because the
     *   credentials provided do not match, or due to insufficient attempts. The user may be prompted
     *   to retry or use other authentication methods if available.
     *
     * - **onErrorAuthenticate**: Called when there is an error during authentication, such as
     *   a system-related issue (e.g., the device doesn’t support device credentials, or the user
     *   cannot authenticate). This callback provides an error code and message detailing the
     *   reason for failure, which can be handled appropriately.
     *
     * - **onNegativeButtonClicked**: Called when the user presses the cancel button (negative action),
     *   which dismisses the authentication prompt and halts the authentication process.
     */
    abstract fun authenticateDeviceCredential(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: WeakAuthenticationCallBack,
    )

    /**
     * Authenticate using biometric authentication (fingerprint or face).
     *
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required for authentication.
     * @param callBack The callback to handle the authentication results:
     *
     * - **onSuccessAuthenticate**: Called when biometric authentication is successful, indicating
     *   that the user’s fingerprint or face was recognized. Upon success, further actions may proceed.
     *
     * - **onFailedAuthenticate**: Called when biometric authentication fails, usually due to an
     *   unrecognized fingerprint or face scan. The user can retry authentication.
     *
     * - **onErrorAuthenticate**: Called when an error occurs during authentication, such as system
     *   issues, sensor malfunction, or unsupported OS versions. Provides an error code and message
     *   explaining the error type. For example:
     *   - Error code for OS not supported if the minimum OS version for biometric authentication is not met.
     *   - Error code and message indicating specific sensor issues or interruptions.
     *
     * - **onNegativeButtonClicked**: Called when the user cancels authentication by pressing the
     *   cancel button. The prompt is dismissed, and the authentication process is stopped.
     */
    abstract fun authenticateBiometric(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: WeakAuthenticationCallBack
    )

    /**
     * Checks if the biometric data on the device has changed.
     *
     * A biometric change is detected if new biometric data (e.g., a fingerprint) has been enrolled on the device.
     * Deleting biometric data is not detected as a change.
     *
     * @param alias The alias of the secret key used to verify biometric integrity.
     *
     * @return true if a biometric change is detected; false otherwise.
     *
     * @throws com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException [com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE] if an error occurs while checking for biometric changes.
     */
    abstract fun isBiometricChanged(alias: String): Boolean

    /**
     * Secure encrypt authenticate using biometric encryption with Default Cipher & Secret Key.
     *
     * Cipher get from [cipher]
     * Secret Key get from [getSecretKey]
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param activity Activity where the biometric prompt happened.
     * @param alias Key Identifier
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The subtitle displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results.
     */
    abstract fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    )

    /**
     * Securely encrypt authenticate using biometric encryption with custom Cipher & Secret Key.
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param activity Activity where the biometric prompt happened.
     * @param title The title displayed in the biometric prompt.
     * @param cipher The cipher from crypto object for handling cryptography data.
     * @param secretKey The secret key used for keep the data secured.
     * @param subTitle The subtitle displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results.
     */
    abstract fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        title: String,
        cipher: Cipher,
        secretKey: SecretKey,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    )

    /**
     * Secure decrypt authenticate using biometric encryption with Default Cipher & Secret Key.
     *
     * Cipher get from [cipher]
     * Secret Key get from [getSecretKey]
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param activity Activity where the biometric prompt happened.
     * @param alias Key Identifier
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The subtitle displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results.
     */
    abstract fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    )

    /**
     * Secure decrypt authenticate using biometric encryption with custom Cipher & Secret Key.
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param activity Activity where the biometric prompt happened.
     * @param title The title displayed in the biometric prompt.
     * @param cipher The cipher from crypto object for handling cryptography data.
     * @param secretKey The secret key used for keep the data secured.
     * @param subTitle The subtitle displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results.
     */
    abstract fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        encodedIVKey: String,
        cipher: Cipher,
        secretKey: SecretKey,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    )

    /**
     * Encrypts a plain text string using the provided cipher.
     *
     * This function takes a `Cipher` initialized for encryption and the plain text to be encrypted.
     * It encrypts the plain text and returns the result as a Base64-encoded string without any extra
     * wrapping or padding.
     *
     * @param cipher The `Cipher` instance initialized in `ENCRYPT_MODE`.
     * @param plainText The plain text string to be encrypted.
     * @return The Base64-encoded encrypted string.
     */
    abstract fun encrypt(cipher: Cipher, plainText: String): String

    /**
     * Decrypts an encrypted byte array using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and the encrypted byte array.
     * It decrypts the byte array and returns the original plain text string. If decryption fails
     * due to incorrect padding, a `FeatureBiometricException` is thrown with the appropriate error message.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedText The encrypted byte array to be decrypted.
     * @return The decrypted plain text string.
     * @throws com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException If the decryption fails due to padding issues (BadPaddingException).
     */
    abstract fun decrypt(cipher: Cipher, encryptedText: ByteArray): String

    /**
     * Decrypts an encrypted text using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and a Base64-encoded encrypted string.
     * It decodes the encrypted string from Base64 to a byte array, and then decrypts it using the
     * `decrypt(cipher, encryptedPassword: ByteArray)` function.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedText The Base64-encoded encrypted string to be decrypted.
     * @return The decrypted plain text string.
     * @throws com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException If the decryption fails due to padding issues.
     */
    abstract fun decrypt(cipher: Cipher, encryptedText: String): String
}