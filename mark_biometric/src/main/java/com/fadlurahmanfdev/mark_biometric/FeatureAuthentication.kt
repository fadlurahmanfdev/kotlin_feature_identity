package com.fadlurahmanfdev.mark_biometric

import android.app.KeyguardManager
import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.hardware.biometrics.BiometricPrompt.CryptoObject
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.fadlurahmanfdev.mark_biometric.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_biometric.core.callback.AuthenticationCallBack
import com.fadlurahmanfdev.mark_biometric.core.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.mark_biometric.core.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.mark_biometric.core.enums.CheckAuthenticationStatusType
import com.fadlurahmanfdev.mark_biometric.core.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.mark_biometric.core.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.mark_biometric.core.exception.FeatureIdentityException
import com.fadlurahmanfdev.mark_biometric.data.repository.FeatureAuthenticationRepository
import java.security.KeyStore
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class FeatureAuthentication(private val context: Context) : FeatureAuthenticationRepository {

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var biometricManager: BiometricManager
    private lateinit var keyguardManager: KeyguardManager

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            fingerprintManager =
                context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            biometricManager =
                context.getSystemService(Context.BIOMETRIC_SERVICE) as BiometricManager

        }

        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }

    private fun getCipher(): Cipher {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_CBC + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
        } else {
            Cipher.getInstance("AES/CBC/PKCS7Padding")
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKeyGenParameterSpec(alias: String): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(true)
            }
        }.build()
    }

    private fun generateSecretKey(alias: String): SecretKey {
        var secretKey: SecretKey? = getSecretKey(alias)

        if (secretKey != null) {
            Log.d(this::class.java.simpleName, "secret key $alias already exist")
            return secretKey
        }

        Log.d(this::class.java.simpleName, "generating new secret key $alias")
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

    private fun getSecretKey(alias: String): SecretKey? {
        var secretKey: SecretKey? = null
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            val existingSecretKey =
                keyStore.getKey(alias, null) as SecretKey?
            if (existingSecretKey != null) {
                Log.d(
                    this::class.java.simpleName,
                    "successfully get existing key - $alias"
                )
                secretKey = existingSecretKey
            }
        } catch (e: Exception) {
            Log.d(
                this::class.java.simpleName,
                "unable to fetch $alias: ${e.message}"
            )
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_FETCH_GET_SECRET_KEY,
                message = e.message
            )
        }
        return secretKey
    }

    /**
     * Deletes an existing key from the Android KeyStore.
     *
     * @param alias The alias of the entry to delete from the KeyStore. Must not be empty.
     *
     * @throws FeatureIdentityException if unable to delete the key, with error code [ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY].
     */
    override fun deleteSecretKey(alias: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            keyStore.deleteEntry(alias)
            Log.d(
                this::class.java.simpleName,
                "successfully delete secret key $alias"
            )
        } catch (e: Exception) {
            Log.e(
                this::class.java.simpleName,
                "failed to delete secret key $alias"
            )
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY,
                message = e.message
            )
        }
    }

    /**
     * Checks if the device supports fingerprint authentication.
     *
     * @return true if the device supports fingerprint authentication; false otherwise.
     */
    override fun isDeviceSupportFingerprint(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return fingerprintManager.isHardwareDetected
        }

        return false
    }

    /**
     * Checks if the device supports face authentication.
     *
     * @return true if the device supports face authentication; false otherwise.
     */
    override fun isDeviceSupportFaceAuth(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) || context.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        } else {
            return context.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        }
    }

    /**
     * Checks if the device supports biometric authentication, either fingerprint or face authentication.
     *
     * @return true if the device supports any biometric feature; false otherwise.
     */
    override fun isDeviceSupportBiometric(): Boolean {
        return (isDeviceSupportFingerprint() || isDeviceSupportFaceAuth())
    }

    /**
     * Checks if the device has at least one fingerprint enrolled.
     *
     * @return true if a fingerprint is enrolled; false otherwise.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    override fun isFingerprintEnrolled(): Boolean {
        return fingerprintManager.hasEnrolledFingerprints()
    }

    /**
     * Checks if the device has a secure credential enrolled (e.g., PIN, password, pattern).
     *
     * @return true if the device has a secure credential enrolled; false otherwise.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    override fun isDeviceCredentialEnrolled(): Boolean {
        return keyguardManager.isDeviceSecure
    }

    private fun checkAuthenticationStatus(
        type: CheckAuthenticationStatusType
    ): FeatureAuthenticationStatus {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authenticatorType = when (type) {
                CheckAuthenticationStatusType.BIOMETRIC_WEAK -> BiometricManager.Authenticators.BIOMETRIC_WEAK
                CheckAuthenticationStatusType.BIOMETRIC_STRONG -> BiometricManager.Authenticators.BIOMETRIC_STRONG
                CheckAuthenticationStatusType.DEVICE_CREDENTIAL -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }

            val authenticatorStatus =
                biometricManager.canAuthenticate(authenticatorType)
            return when (authenticatorStatus) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    FeatureAuthenticationStatus.SUCCESS
                }

                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    FeatureAuthenticationStatus.NO_HARDWARE
                }

                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    FeatureAuthenticationStatus.UNAVAILABLE
                }

                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    FeatureAuthenticationStatus.NONE_ENROLLED
                }

                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                    FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED
                }

                else -> {
                    FeatureAuthenticationStatus.UNKNOWN
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            when (type) {
                CheckAuthenticationStatusType.BIOMETRIC_WEAK, CheckAuthenticationStatusType.BIOMETRIC_STRONG -> {
                    val isEnrolled = isFingerprintEnrolled()
                    return if (isEnrolled) {
                        FeatureAuthenticationStatus.SUCCESS
                    } else {
                        FeatureAuthenticationStatus.NONE_ENROLLED
                    }
                }

                CheckAuthenticationStatusType.DEVICE_CREDENTIAL -> {
                    val isEnrolled = isDeviceCredentialEnrolled()
                    return if (isEnrolled) {
                        FeatureAuthenticationStatus.SUCCESS
                    } else {
                        FeatureAuthenticationStatus.NONE_ENROLLED
                    }
                }
            }
        }

        return FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION
    }

    /**
     * Checks the status of the specified authenticator.
     *
     * @param authenticatorType The type of authenticator (biometric or device credential).
     *
     * @return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate using the specified authenticator;
     * [FeatureAuthenticationStatus.NONE_ENROLLED] if the device has no enrolled data for the specified authenticator;
     * [FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks the hardware for the specified authenticator;
     * [FeatureAuthenticationStatus.UNAVAILABLE] if the device is currently unable to authenticate with the specified authenticator;
     * [FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for the device to authenticate;
     * [FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support authentication;
     * [FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    override fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus {
        return when (authenticatorType) {
            FeatureAuthenticatorType.BIOMETRIC -> checkAuthenticationStatus(type = CheckAuthenticationStatusType.BIOMETRIC_WEAK)
            FeatureAuthenticatorType.DEVICE_CREDENTIAL -> checkAuthenticationStatus(type = CheckAuthenticationStatusType.DEVICE_CREDENTIAL)
        }
    }

    /**
     * Checks the status of secure authentication on the device.
     *
     * @return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate securely;
     * [FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks hardware for secure authentication;
     * [FeatureAuthenticationStatus.UNAVAILABLE] if secure authentication is currently unavailable;
     * [FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for secure authentication;
     * [FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support secure authentication;
     * [FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    override fun checkSecureAuthentication(): FeatureAuthenticationStatus {
        return checkAuthenticationStatus(type = CheckAuthenticationStatusType.BIOMETRIC_STRONG)
    }

    /**
     * Determines whether the device can authenticate using the specified authenticator.
     *
     * @param authenticatorType The type of authenticator (biometric or device credential).
     *
     * @return true if the device can authenticate using the specified authenticator; false otherwise.
     */
    override fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean {
        return checkAuthenticatorStatus(authenticatorType) == FeatureAuthenticationStatus.SUCCESS
    }

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
    @RequiresApi(Build.VERSION_CODES.R)
    override fun authenticateDeviceCredential(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    ) {
        generalAuthenticateBiometricAndroidP(
            title = title,
            subTitle = subTitle,
            description = description,
            authenticator = BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            negativeText = negativeText,
            setConfirmationRequired = confirmationRequired,
            cryptoObject = null,
            negativeButtonCallback = object : DialogInterface.OnClickListener {
                override fun onClick(dialog: DialogInterface?, which: Int) {
                    println("MASUK WHICH")
                }
            },
            callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    callBack.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callBack.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (errorCode == 10) {
                        callBack.onCanceled()
                    } else {
                        callBack.onErrorAuthenticate(
                            FeatureIdentityException(
                                code = "$errorCode",
                                message = errString.toString()
                            )
                        )
                    }
                }
            }
        )
    }

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
    override fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            var authenticator = -1
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                authenticator = BiometricManager.Authenticators.BIOMETRIC_WEAK
            }
            generalAuthenticateBiometricAndroidP(
                title = title,
                subTitle = subTitle,
                description = description,
                authenticator = authenticator,
                negativeText = negativeText,
                setConfirmationRequired = confirmationRequired,
                cryptoObject = null,
                negativeButtonCallback = object : DialogInterface.OnClickListener {
                    override fun onClick(dialog: DialogInterface?, which: Int) {
                        callBack.onNegativeButtonClicked(which)
                    }
                },
                callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        callBack.onSuccessAuthenticate()
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        callBack.onFailedAuthenticate()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        if (errorCode == 10) {
                            callBack.onCanceled()
                        } else {
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                }
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generalAuthenticateAndroidM(
                null,
                object : FingerprintManager.AuthenticationCallback() {
                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                        super.onAuthenticationSucceeded(result)
                        callBack.onSuccessAuthenticate()
                    }

                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        callBack.onFailedAuthenticate()
                    }

                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        super.onAuthenticationError(errorCode, errString)
                        callBack.onErrorAuthenticate(
                            FeatureIdentityException(
                                code = "$errorCode",
                                message = errString?.toString(),
                            )
                        )
                    }
                }
            )
        } else {
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.OS_NOT_SUPPORTED,
                    message = "OS not supported"
                )
            )
        }
    }

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
     * @throws FeatureIdentityException [ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE] if an error occurs while checking for biometric changes.
     */
    override fun isBiometricChanged(alias: String): Boolean {
        try {
            val cipher = getCipher()
            val secretKey = getSecretKey(alias = alias)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return false
        } catch (e: FeatureIdentityException) {
            throw e
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    return true
                }
            }
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE,
                message = e.message,
            )
        }
    }

    /**
     * Securely authenticate using biometric encryption.
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param alias The alias of the secret key used for encryption. If the key is invalidated, the user must delete it
     *              and generate a new one to continue using secure authentication.
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results, including:
     *
     * - **onSuccessAuthenticate**: Called when biometric authentication is successful. This callback provides
     *   the encrypted cipher and IV (Initialization Vector) in Base64 format, allowing further secure operations.
     *
     * - **onFailedAuthenticate**: Called when biometric authentication fails, typically due to unrecognized biometric data.
     *   The user can attempt authentication again if desired.
     *
     * - **onErrorAuthenticate**: Called when an error occurs during authentication. Provides a code and message detailing
     *   the error, such as:
     *   - **Error Constant `KEY_PERMANENTLY_INVALIDATED`**: This occurs if the key has been invalidated. For example, adding
     *     or removing fingerprints will invalidate the key, requiring the user to delete the existing key and generate a
     *     new one with the same alias.
     *   - **Error Constant `CIPHER_MISSING`**: Indicates a missing cipher, which is required for secure authentication.
     *   - **Error Constant `OS_NOT_SUPPORTED`**: Returned when the device OS version does not support the necessary
     *     biometric functionality.
     *   - **General Exception**: If another exception is caught, an error message will indicate the issue (e.g., encryption setup errors).
     *
     * - **onNegativeButtonClicked**: Called when the user presses the cancel button on the biometric prompt, halting the
     *   authentication process.
     */
    override fun secureAuthenticateBiometricEncrypt(
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    ) {
        try {
            val cipher = getCipher()
            var secretKey = getSecretKey(alias = alias)

            if (secretKey == null) {
                secretKey = generateSecretKey(alias)
            }

            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                generalAuthenticateBiometricAndroidP(
                    title = title,
                    subTitle = subTitle,
                    description = description,
                    authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                    negativeText = negativeText,
                    setConfirmationRequired = confirmationRequired,
                    cryptoObject = BiometricPrompt.CryptoObject(cipher),
                    negativeButtonCallback = object :DialogInterface.OnClickListener {
                        override fun onClick(dialog: DialogInterface?, which: Int) {
                            callBack.onNegativeButtonClicked(which)
                        }

                    },
                    callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            if (result.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject!!.cipher
                            val encodedIvKey =
                                Base64.encodeToString(cipherResult!!.iv, Base64.NO_WRAP)
                            callBack.onSuccessAuthenticate(
                                cipherResult,
                                encodedIvKey
                            )
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generalAuthenticateAndroidM(
                    FingerprintManager.CryptoObject(cipher),
                    object : FingerprintManager.AuthenticationCallback() {
                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            val encodedIvKey =
                                Base64.encodeToString(cipherResult.iv, Base64.NO_WRAP)
                            callBack.onSuccessAuthenticate(
                                cipherResult,
                                encodedIvKey
                            )
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString(),
                                )
                            )
                        }
                    }
                )
            } else {
                callBack.onErrorAuthenticate(
                    FeatureIdentityException(
                        code = ErrorConstant.OS_NOT_SUPPORTED,
                        message = "OS not supported"
                    )
                )
            }
        } catch (e: FeatureIdentityException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    callBack.onErrorAuthenticate(
                        FeatureIdentityException(
                            code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                            message = e.message,
                        )
                    )
                    return
                }
            }
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.message,
                )
            )
        }
    }

    /**
     * Securely authenticate using biometric decryption.
     *
     * This method decrypts data using a biometric-protected secret key. If the key is invalidated
     * (e.g., due to biometric changes like adding a new fingerprint), it cannot be used for decryption.
     * In such cases, users must generate a new key and re-encrypt the data.
     *
     * @param alias The alias of the secret key used for decryption.
     * @param encodedIVKey The IV key obtained from encryption, encoded as a string.
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results, including the decrypted cipher.
     *
     * `callBack` provides the following methods:
     * - `onSuccessAuthenticate(cipher: Cipher)`: Called when authentication is successful. The provided
     *   `cipher` can be used to securely decrypt the data using the correct secret key.
     * - `onErrorAuthenticate(exception: FeatureIdentityException)`: Called when an error occurs during
     *   authentication. The exception details the cause of failure, such as:
     *      - `ErrorConstant.SECRET_KEY_MISSING`: The required secret key is missing. Re-encryption
     *        with a new key may be necessary.
     *      - `ErrorConstant.CIPHER_MISSING`: Cipher was not properly initialized for secure decryption.
     *      - `ErrorConstant.KEY_PERMANENTLY_INVALIDATED`: The key is invalidated due to biometric changes
     *        (e.g., new fingerprint added). A new key must be generated to proceed.
     *      - `ErrorConstant.UNABLE_SECURE_AUTHENTICATE`: A generic error, often caused by device or
     *        OS issues.
     * - `onFailedAuthenticate()`: Called when biometric authentication fails but no critical error
     *   occurs. This typically means the user did not authenticate successfully, and they may retry.
     * - `onNegativeButtonClicked(which: Int)`: Called when the user taps the negative button (e.g.,
     *   "Cancel") on the biometric prompt. This cancels the authentication process.
     */
    override fun secureAuthenticateBiometricDecrypt(
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    ) {
        try {
            val cipher = getCipher()
            val secretKey = getSecretKey(alias = alias)
                ?: throw FeatureIdentityException(
                    code = ErrorConstant.SECRET_KEY_MISSING,
                    message = "Cannot proceed to the next page caused by secret key null"
                )

            val ivKey = Base64.decode(encodedIVKey, Base64.NO_WRAP)
            val ivSpec = IvParameterSpec(ivKey)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                generalAuthenticateBiometricAndroidP(
                    title = title,
                    subTitle = subTitle,
                    description = description,
                    authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                    negativeText = negativeText,
                    setConfirmationRequired = confirmationRequired,
                    cryptoObject = BiometricPrompt.CryptoObject(cipher),
                    negativeButtonCallback = object : DialogInterface.OnClickListener {
                        override fun onClick(dialog: DialogInterface?, which: Int) {
                            callBack.onNegativeButtonClicked(which)
                        }

                    },
                    callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            if (result.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject!!.cipher
                            callBack.onSuccessAuthenticate(cipherResult!!)
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generalAuthenticateAndroidM(
                    FingerprintManager.CryptoObject(cipher),
                    object : FingerprintManager.AuthenticationCallback() {
                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            callBack.onSuccessAuthenticate(cipherResult)
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString(),
                                )
                            )
                        }
                    }
                )
            } else {
                callBack.onErrorAuthenticate(
                    FeatureIdentityException(
                        code = ErrorConstant.OS_NOT_SUPPORTED,
                        message = "OS not supported"
                    )
                )
            }
        } catch (e: FeatureIdentityException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    callBack.onErrorAuthenticate(
                        FeatureIdentityException(
                            code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                            message = e.message,
                        )
                    )
                    return
                }
            }
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.message,
                )
            )
        }
    }

    //    @RequiresApi(Build.VERSION_CODES.P)
    @RequiresApi(Build.VERSION_CODES.P)
    private fun generalAuthenticateBiometricAndroidP(
        callback: BiometricPrompt.AuthenticationCallback,
        negativeButtonCallback: DialogInterface.OnClickListener,
        cryptoObject: CryptoObject?,
        setConfirmationRequired: Boolean = false,
        authenticator: Int,
        title: String,
        subTitle: String? = null,
        description: String,
        negativeText: String,
    ) {
        val cancellationSignal = CancellationSignal()
        val executor = ContextCompat.getMainExecutor(context)
        val prompt = BiometricPrompt.Builder(context)
            .setTitle(title)
            .apply {
                if (!subTitle.isNullOrEmpty()) {
                    setSubtitle(subTitle)
                }
            }
            .setDescription(description)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setAllowedAuthenticators(authenticator)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setConfirmationRequired(setConfirmationRequired)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    if (authenticator != BiometricManager.Authenticators.DEVICE_CREDENTIAL) {
                        setNegativeButton(negativeText, executor, negativeButtonCallback)
                    }
                }
            }
            .build()

        if (cryptoObject != null) {
            prompt.authenticate(
                cryptoObject,
                cancellationSignal,
                executor,
                callback
            )
        } else {
            prompt.authenticate(cancellationSignal, executor, callback)
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generalAuthenticateAndroidM(
        cryptoObject: FingerprintManager.CryptoObject?,
        callback: FingerprintManager.AuthenticationCallback,
    ) {
        val cancellationSignal = CancellationSignal()
        val handler = Handler(Looper.getMainLooper())
        fingerprintManager.authenticate(
            cryptoObject,
            cancellationSignal,
            0,
            callback,
            handler

        )
    }

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
    override fun encrypt(cipher: Cipher, plainText: String): String {
        val byteEncryptedText = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(byteEncryptedText, Base64.NO_WRAP)
    }

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
     * @throws FeatureIdentityException If the decryption fails due to padding issues (BadPaddingException).
     */
    override fun decrypt(cipher: Cipher, encryptedText: ByteArray): String {
        try {
            return String(cipher.doFinal(encryptedText))
        } catch (e: BadPaddingException) {
            throw FeatureIdentityException(
                code = ErrorConstant.BAD_PADDING,
                message = e.message,
            )
        }
    }

    /**
     * Decrypts an encrypted Base64-encoded string using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and a Base64-encoded encrypted string.
     * It decodes the encrypted string from Base64 to a byte array, and then decrypts it using the
     * `decrypt(cipher, encryptedPassword: ByteArray)` function.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedText The Base64-encoded encrypted string to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureIdentityException If the decryption fails due to padding issues.
     */
    override fun decrypt(cipher: Cipher, encryptedText: String): String {
        val decodedText =
            Base64.decode(encryptedText, Base64.NO_WRAP)
        return decrypt(cipher = cipher, encryptedText = decodedText)
    }
}