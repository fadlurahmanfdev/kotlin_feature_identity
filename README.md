# Description
Mark Authenticator is a library that handle identity/authentication related, such as biometric, device 
credential, etc.

# Method

## Delete Secret Key

Deletes an existing key from the Android KeyStore.

## Is Device Support Fingerprint ?

Checks if the device supports fingerprint authentication.

```kotlin
val isSupportFingerprint = markAuthenticator.isDeviceSupportFingerprint()
```

## Is Device Support Face Auth ?

Checks if the device supports face authentication.

```kotlin
val isSupportFaceAuth = markAuthenticator.isDeviceSupportFaceAuth()
```

## Is Device Support Biometric ?

Checks if the device supports biometric authentication, either fingerprint or face authentication.

```kotlin
val isSupportBiometric = markAuthenticator.isDeviceSupportBiometric()
```

## Is Biometric Enrolled ?

Checks if the device has at least one biometric enrolled.

```kotlin
val isEnrolled = markAuthenticator.isBiometricEnrolled()
```

## Is Device Credential Enrolled ?

Determines the device's credential is enrolled (PIN, Password, etc)

```kotlin
val isEnrolled = markAuthenticator.isDeviceCredentialEnrolled()
```

## Check Authenticator Status

Checks the authenticator status based on authenticator method (biometric or device credential)

Return:
- `MarkAuthenticatorStatus.SUCCESS` - if the device can authenticate using the specified authenticator.
- `MarkAuthenticatorStatus.NONE_ENROLLED` - if the device has no enrolled data for the specified authenticator.
- `MarkAuthenticatorStatus.NO_HARDWARE` - if the device lacks the hardware for the specified authenticator.
- `MarkAuthenticatorStatus.UNAVAILABLE` - if the device is currently unable to authenticate with the specified authenticator.
- `MarkAuthenticatorStatus.SECURITY_UPDATE_REQUIRED` - if a security update is required for the device to authenticate.
- `MarkAuthenticatorStatus.UNSUPPORTED_OS_VERSION` - if the OS version does not support authentication.
- `MarkAuthenticatorStatus.UNKNOWN` - if an unknown status is encountered.

```kotlin
val biometricAuthenticatorStatus = markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)
val deviceCredentialStatus = markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
```

## Can Authenticate

Determines whether the device can authenticate using the specified authenticator (biometric or device credential).

Return true if the device can authenticate using the specified authenticator; false otherwise.

```kotlin
val canAuthenticateBiometric = markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.BIOMETRIC)
val canAuthenticateDeviceCredential = markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
```

## Authenticate Using Weak Biometric

Authenticate using biometric authentication (fingerprint or face).

```kotlin
markAuthenticator.authenticateBiometric(
    title = "Title Biometric",
    description = "Desc Biometric",
    subTitle = "SubTitle Biometric",
    negativeText = "Negative Text",
    confirmationRequired = true,
    callBack = object : WeakAuthenticationCallBack {
        override fun onSuccessAuthenticate() {
            // on success authenticate
        }

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
            // on error authenticate
        }

        override fun onFailedAuthenticate() {
            // on failed authenticate
        }

        override fun onCanceled() {
            // on canceled authenticate
        }

        override fun onNegativeButtonClicked(which: Int) {
            // on negative button clicked
        }
    }
)
```


## Authenticate using Device Credential

Authenticate using device credentials.

```kotlin
markAuthenticator.authenticateDeviceCredential(
                    activity = this,
                    title = "Title - Device Credential",
                    subTitle = "Sub Title - Device Credential",
                    description = "Desc - Device Credential",
                    negativeText = "Negative Text",
                    confirmationRequired = true,
                    callBack = object : WeakAuthenticationCallBack {
                        override fun onSuccessAuthenticate() {
                            // on success authenticate
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            // on error authenticate
                        }

                        override fun onFailedAuthenticate() {
                            // on failed authenticate
                        }

                        override fun onCanceled() {
                            super.onCanceled()
                            // on canceled
                        }
                    }
                )
```

## Is Biometric Changed ?

Checks if the biometric data on the device has changed.

A biometric change is detected if new biometric data (e.g., a fingerprint) has been enrolled on the device. 
Deleting biometric data is not detected as a change.

```kotlin
val isBiometricChanged = markAuthenticator.isBiometricChanged("{alias}")
```

## Authenticate Encrypt Biometric

Securely authenticate using biometric encryption.

This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
(e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.

```kotlin
markAuthenticator.secureAuthenticateBiometricEncrypt(
                    activity = this,
                    title = "Title - Encrypt Biometric",
                    subTitle = "Sub Title - Encrypt Biometric",
                    description = "Desc - Encrypt Biometric",
                    negativeText = "Cancel",
                    alias = "{alias}",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationEncryptCallBack {
                        override fun onSuccessAuthenticate(
                            cipher: Cipher,
                            encodedIVKey: String
                        ) {
                            encodedEncryptedPassword = markAuthenticator.encrypt(cipher, plainText)
                            this@MainActivity.encodedIvKey = encodedIVKey
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            // on error authenticate
                        }

                        override fun onFailedAuthenticate() {
                            // on failed authenticate
                        }
                    }
                )
```


## Authenticate Decrypt Biometric

Securely authenticate using biometric decryption.

This method decrypts data using a biometric-protected secret key. If the key is invalidated
(e.g., due to biometric changes like adding a new fingerprint), it cannot be used for decryption.
In such cases, users must generate a new key and re-encrypt the data.

```kotlin
markAuthenticator.secureAuthenticateBiometricDecrypt(
                    activity = this,
                    alias = "{key alias}",
                    encodedIVKey = encodedIvKey,
                    title = "Title - Decrypt Biometric",
                    subTitle = "Sub Title - Decrypt Biometric",
                    description = "Desc - Decrypt Biometric",
                    negativeText = "Cancel",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationDecryptCallBack {
                        override fun onSuccessAuthenticate(cipher: Cipher) {
                            val plainPassword =
                                markAuthenticator.decrypt(cipher, encodedEncryptedPassword)
                            // on success authenticate
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            // on error authenticate
                        }

                        override fun onFailedAuthenticate() {
                            // on failed authenticate
                        }
                    }
                )
```