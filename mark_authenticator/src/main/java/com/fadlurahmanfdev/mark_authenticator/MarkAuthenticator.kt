package com.fadlurahmanfdev.mark_authenticator

import android.app.Activity
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
import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.base.BaseMarkAuthenticator
import com.fadlurahmanfdev.mark_authenticator.core.callback.WeakAuthenticationCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticationType
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticatorMethod
import com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException
import java.security.InvalidKeyException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MarkAuthenticator(private val context: Context) : BaseMarkAuthenticator() {

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

    /**
     * Cipher used for secure authentication
     * */
    override fun cipher(): Cipher {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Cipher.getInstance(
                KeyProperties.KEY_ALGORITHM_AES + "/"
                        + KeyProperties.BLOCK_MODE_GCM + "/"
                        + KeyProperties.ENCRYPTION_PADDING_NONE
            )
        } else {
            Cipher.getInstance("AES/GCM/NoPadding")
        }
    }

    /**
     * Generate Secret Key with AES Algorithm
     *
     * @param alias the key identifier
     *
     * @throws MarkAuthenticatorException if the specific alias key already exist before with code [ErrorConstant.SECRET_KEY_ALREADY_EXIST]
     * */
    override fun generateSecretKey(alias: String): SecretKey {
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
     * Checks if the device has at least one biometric enrolled.
     *
     * @return true if a fingerprint is enrolled; false otherwise.
     */
    override fun isBiometricEnrolled(): Boolean =
        checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC) == MarkAuthenticationStatus.SUCCESS

    /**
     * Checks if the device has a secure credential enrolled (e.g., PIN, password, pattern).
     *
     * @return true if the device has a secure credential enrolled; false otherwise.
     */
    override fun isDeviceCredentialEnrolled(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguardManager.isDeviceSecure
        } else {
            checkAuthenticatorStatus(MarkAuthenticatorMethod.DEVICE_CREDENTIAL) == MarkAuthenticationStatus.SUCCESS
        }
    }

    private fun checkAuthenticatorStatusByAuthenticatorType(
        type: MarkAuthenticationType
    ): MarkAuthenticationStatus {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authenticatorType = when (type) {
                MarkAuthenticationType.BIOMETRIC_WEAK -> BiometricManager.Authenticators.BIOMETRIC_WEAK
                MarkAuthenticationType.BIOMETRIC_STRONG -> BiometricManager.Authenticators.BIOMETRIC_STRONG
                MarkAuthenticationType.DEVICE_CREDENTIAL -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }

            val authenticatorStatus =
                biometricManager.canAuthenticate(authenticatorType)
            return when (authenticatorStatus) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    MarkAuthenticationStatus.SUCCESS
                }

                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    MarkAuthenticationStatus.NO_HARDWARE
                }

                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    MarkAuthenticationStatus.UNAVAILABLE
                }

                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    MarkAuthenticationStatus.NONE_ENROLLED
                }

                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                    MarkAuthenticationStatus.SECURITY_UPDATE_REQUIRED
                }

                else -> {
                    MarkAuthenticationStatus.UNKNOWN
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            when (type) {
                MarkAuthenticationType.BIOMETRIC_WEAK, MarkAuthenticationType.BIOMETRIC_STRONG -> {
                    val isEnrolled = isBiometricEnrolled()
                    return if (isEnrolled) {
                        MarkAuthenticationStatus.SUCCESS
                    } else {
                        MarkAuthenticationStatus.NONE_ENROLLED
                    }
                }

                MarkAuthenticationType.DEVICE_CREDENTIAL -> {
                    val isEnrolled = isDeviceCredentialEnrolled()
                    return if (isEnrolled) {
                        MarkAuthenticationStatus.SUCCESS
                    } else {
                        MarkAuthenticationStatus.NONE_ENROLLED
                    }
                }
            }
        }

        return MarkAuthenticationStatus.UNSUPPORTED_OS_VERSION
    }

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
    override fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus {
        return when (method) {
            MarkAuthenticatorMethod.BIOMETRIC -> checkAuthenticatorStatusByAuthenticatorType(type = MarkAuthenticationType.BIOMETRIC_WEAK)
            MarkAuthenticatorMethod.DEVICE_CREDENTIAL -> checkAuthenticatorStatusByAuthenticatorType(
                type = MarkAuthenticationType.DEVICE_CREDENTIAL
            )
        }
    }

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
    override fun checkSecureAuthentication(): MarkAuthenticationStatus {
        return checkAuthenticatorStatusByAuthenticatorType(type = MarkAuthenticationType.BIOMETRIC_STRONG)
    }

    /**
     * Determines whether the device can authenticate using the specified authenticator.
     *
     * @param method The method of authenticator (biometric or device credential).
     *
     * @return true if the device can authenticate using the specified authenticator; false otherwise.
     */
    override fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean {
        return checkAuthenticatorStatus(method) == MarkAuthenticationStatus.SUCCESS
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
    override fun authenticateDeviceCredential(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: WeakAuthenticationCallBack
    ) {
        generalAuthenticateBiometricAndroidX(
            activity = activity,
            cryptoObject = null,
            confirmationRequired = confirmationRequired,
            authenticator = androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            title = title,
            description = description,
            subTitle = subTitle,
            negativeText = negativeText,
            callback = object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    callBack.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callBack.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (errorCode == 13) {
                        callBack.onCanceled()
                    } else {
                        callBack.onErrorAuthenticate(
                            MarkAuthenticatorException(
                                code = errorCode.toString(),
                                message = errString.toString(),
                                cause = null,
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
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: WeakAuthenticationCallBack
    ) {
        generalAuthenticateBiometricAndroidX(
            activity = activity,
            cryptoObject = null,
            confirmationRequired = confirmationRequired,
            authenticator = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK,
            title = title,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            callback = object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    callBack.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callBack.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (errorCode == 13) {
                        callBack.onCanceled()
                    } else {
                        callBack.onErrorAuthenticate(
                            MarkAuthenticatorException(
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
     * Checks if the biometric data on the device has changed.
     *
     * A biometric change is detected if new biometric data (e.g., a fingerprint) has been enrolled on the device.
     * Deleting biometric data is not detected as a change.
     *
     * @param alias The alias of the secret key used to verify biometric integrity.
     *
     * @return true if a biometric change is detected; false otherwise.
     *
     * @throws MarkAuthenticatorException [ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE] if an error occurs while checking for biometric changes.
     */
    override fun isBiometricChanged(alias: String): Boolean {
        try {
            val cipher = cipher()
            val secretKey = getSecretKey(alias = alias)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return false
        } catch (e: MarkAuthenticatorException) {
            throw e
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    return true
                }
            }

            if (e is InvalidKeyException) {
                Log.w(
                    this::class.java.simpleName,
                    "MarkAuthenticator-LOG %%% key with specific alias is missing, probably never register key with specific alias"
                )
                return false
            }

            Log.e(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% failed to detect biometric changes caused by ${e.toString()}"
            )
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE,
                message = e.toString(),
            )
        }
    }

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
    override fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    ) {
        var secretKey = getSecretKey(alias = alias)

        if (secretKey == null) {
            secretKey = generateSecretKey(alias)
        }

        val cipher = cipher()

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        secureAuthenticateBiometricEncrypt(
            activity = activity,
            title = title,
            cipher = cipher,
            secretKey = secretKey,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            callBack = callBack,
        )
    }

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
    override fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        title: String,
        cipher: Cipher,
        secretKey: SecretKey,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    ) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            generalAuthenticateBiometricAndroidX(
                activity = activity,
                cryptoObject = androidx.biometric.BiometricPrompt.CryptoObject(cipher),
                confirmationRequired = confirmationRequired,
                authenticator = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
                title = title,
                subTitle = subTitle,
                description = description,
                negativeText = negativeText,
                callback = object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cipherResult = result.cryptoObject?.cipher
                        if (cipherResult == null) {
                            callBack.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = ErrorConstant.CIPHER_MISSING,
                                    message = "Cipher missing for secure authentication"
                                )
                            )
                            return
                        }

                        val encodedIvKey = Base64.encodeToString(cipherResult.iv, Base64.NO_WRAP)
                        callBack.onSuccessAuthenticate(cipher, encodedIvKey)
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
                        if (errorCode == 13) {
                            callBack.onCanceled()
                        } else {
                            callBack.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                }
            )
        } catch (e: Throwable) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    callBack.onErrorAuthenticate(
                        MarkAuthenticatorException(
                            code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                            message = e.message,
                            cause = e,
                        )
                    )
                    return
                }
            }
            callBack.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.toString(),
                    cause = e
                )
            )
        }
    }

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
    override fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    ) {
        val cipher = cipher()

        val secretKey =
            getSecretKey(alias = alias) ?: throw MarkAuthenticatorException(
                code = ErrorConstant.SECRET_KEY_MISSING,
                message = "Secret Key Missing, probably secret key not registered yet"
            )

        secureAuthenticateBiometricDecrypt(
            activity = activity,
            encodedIVKey = encodedIVKey,
            cipher = cipher,
            secretKey = secretKey,
            title = title,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            callBack = callBack,
        )
    }

    /**
     * Securely decrypt authenticate using biometric encryption with custom Cipher & Secret Key.
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
    override fun secureAuthenticateBiometricDecrypt(
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
    ) {
        try {
            val ivKey = Base64.decode(encodedIVKey, Base64.NO_WRAP)
            val ivSpec = GCMParameterSpec(128, ivKey)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

            generalAuthenticateBiometricAndroidX(
                activity = activity,
                cryptoObject = androidx.biometric.BiometricPrompt.CryptoObject(cipher),
                confirmationRequired = confirmationRequired,
                authenticator = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG,
                title = title,
                subTitle = subTitle,
                description = description,
                negativeText = negativeText,
                callback = object : androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        val cipherResult = result.cryptoObject?.cipher
                        if (cipherResult == null) {
                            callBack.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = ErrorConstant.CIPHER_MISSING,
                                    message = "Cipher missing for secure authentication"
                                )
                            )
                            return
                        }

                        callBack.onSuccessAuthenticate(cipherResult)
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
                        if (errorCode == 13) {
                            callBack.onCanceled()
                        } else {
                            callBack.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                }
            )
        } catch (e: Throwable) {
            Log.wtf(
                this::class.java.simpleName,
                "MarkAuthenticator-LOG %%% failed to secure authenticate caused by ${e.toString()}"
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    callBack.onErrorAuthenticate(
                        MarkAuthenticatorException(
                            code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                            message = e.message,
                        )
                    )
                    return
                }
            }
            callBack.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.message,
                )
            )
        }
    }

    private fun generalAuthenticateBiometricAndroidX(
        activity: FragmentActivity,
        callback: androidx.biometric.BiometricPrompt.AuthenticationCallback,
        cryptoObject: androidx.biometric.BiometricPrompt.CryptoObject?,
        confirmationRequired: Boolean = false,
        authenticator: Int,
        title: String,
        subTitle: String? = null,
        description: String,
        negativeText: String,
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val promptInfo = androidx.biometric.BiometricPrompt.PromptInfo.Builder().apply {
            setTitle(title)
                .setDescription(description)
            if (!subTitle.isNullOrEmpty()) {
                setSubtitle(subTitle)
            }
            setNegativeButtonText(negativeText)
            setAllowedAuthenticators(authenticator)
            setConfirmationRequired(confirmationRequired)
        }.build()

        val biometricPrompt = androidx.biometric.BiometricPrompt(activity, executor, callback)

        if (cryptoObject != null) {
            biometricPrompt.authenticate(promptInfo, cryptoObject)
        } else {
            biometricPrompt.authenticate(promptInfo)
        }
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
     * @throws MarkAuthenticatorException If the decryption fails due to padding issues (BadPaddingException).
     */
    override fun decrypt(cipher: Cipher, encryptedText: ByteArray): String {
        try {
            return String(cipher.doFinal(encryptedText))
        } catch (e: BadPaddingException) {
            throw MarkAuthenticatorException(
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
     * @throws MarkAuthenticatorException If the decryption fails due to padding issues.
     */
    override fun decrypt(cipher: Cipher, encryptedText: String): String {
        val decodedText =
            Base64.decode(encryptedText, Base64.NO_WRAP)
        return decrypt(cipher = cipher, encryptedText = decodedText)
    }
}