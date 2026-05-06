package com.fadlurahmanfdev.example

import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.presentation.ListExampleAdapter
import com.fadlurahmanfdev.mark_authenticator.core.callback.AuthenticationCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticatorMethod
import com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException
import com.fadlurahmanfdev.mark_authenticator.MarkAuthenticator
import com.fadlurahmanfdev.mark_authenticator.MarkAuthenticatorUtils
import javax.crypto.Cipher

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var markAuthenticator: MarkAuthenticator

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Fingerprint?",
            desc = "Check whether device support fingerprint",
            enum = "DEVICE_SUPPORT_FINGERPRINT"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Face Authentication?",
            desc = "Check whether device support face authentication",
            enum = "DEVICE_SUPPORT_FACE_AUTHENTICATION"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Biometric?",
            desc = "Check whether device support biometric",
            enum = "DEVICE_SUPPORT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Fingerprint Enrolled?",
            desc = "Check whether fingerprint enrolled",
            enum = "IS_FINGERPRINT_ENROLLED"
        ),


        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Check Biometric Authentication Status",
            desc = "Check status biometric authentication",
            enum = "CHECK_BIOMETRIC_AUTHENTICATION_STATUS"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Check Device Credential Authentication Status",
            desc = "Check whether device can authenticate using Device Credential",
            enum = "CHECK_DEVICE_CREDENTIAL_AUTHENTICATION_STATUS"
        ),


        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "---------------------DIVIDER-------------------",
            desc = "-------------------------------------------------------------------------",
            enum = "DIVIDER"
        ),

        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Weak Biometric",
            desc = "Prompt Weak Biometric (Fingerprint & Face Recognition)",
            enum = "PROMPT_WEAK_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Credential Biometric",
            desc = "Prompt Credential Biometric (Device Password)",
            enum = "PROMPT_CREDENTIAL_BIOMETRIC"
        ),

        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Biometric Changed?",
            desc = "Check whether new fingerprint/biometric added/changed",
            enum = "IS_BIOMETRIC_CHANGED"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Delete Secret Key",
            desc = "Delete secret key",
            enum = "DELETE_SECRET_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "---------------------DIVIDER-------------------",
            desc = "-------------------------------------------------------------------------",
            enum = "DIVIDER"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypted Biometric",
            desc = "Prompt encrypted biometric",
            enum = "PROMPT_ENCRYPT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Decrypted Biometric",
            desc = "Prompt decrypted biometric",
            enum = "PROMPT_DECRYPT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypt Biometric",
            desc = "Prompt encrypt biometric with custom parameter",
            enum = "PROMPT_ENCRYPT_BIOMETRIC_WITH_CUSTOM_PARAMETER"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Decrypt Biometric",
            desc = "Prompt decrypt biometric with custom parameter",
            enum = "PROMPT_DECRYPT_BIOMETRIC_WITH_CUSTOM_PARAMETER"
        ),
    )

    private lateinit var rv: RecyclerView

    private lateinit var adapter: ListExampleAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        rv = findViewById<RecyclerView>(R.id.rv)

        rv.setItemViewCacheSize(features.size)
        rv.setHasFixedSize(true)

        adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(features)
        rv.adapter = adapter
        markAuthenticator = MarkAuthenticator(this)
    }

    private lateinit var cancellationSignal: CancellationSignal
    private val plainText = "PASSW0RD"
    private lateinit var encodedEncryptedPassword: String
    private lateinit var encodedIvKey: String

    override fun onClicked(item: FeatureModel) {
        when (item.enum) {
            "DEVICE_SUPPORT_FINGERPRINT" -> {
                val isSupported = markAuthenticator.isDeviceSupportFingerprint()
                Log.d(
                    this::class.java.simpleName,
                    "is device support fingerprint: $isSupported"
                )
            }

            "DEVICE_SUPPORT_FACE_AUTHENTICATION" -> {
                val isSupported = markAuthenticator.isDeviceSupportFaceAuth()
                Log.d(
                    this::class.java.simpleName,
                    "is device support face auth: $isSupported"
                )
            }

            "DEVICE_SUPPORT_BIOMETRIC" -> {
                val isSupported = markAuthenticator.isDeviceSupportBiometric()
                Log.d(
                    this::class.java.simpleName,
                    "is device support biometric: $isSupported"
                )
            }

            "IS_FINGERPRINT_ENROLLED" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val isEnrolled = markAuthenticator.isFingerprintEnrolled()
                    Log.d(
                        this::class.java.simpleName,
                        "is fingerprint enrolled: $isEnrolled"
                    )
                }
            }

            "CHECK_BIOMETRIC_AUTHENTICATION_STATUS" -> {
                val status =
                    markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)
                Log.d(
                    this::class.java.simpleName,
                    "App-Example-LOG %%% biometric authentication status: $status"
                )
            }

            "CHECK_DEVICE_CREDENTIAL_AUTHENTICATION_STATUS" -> {
                val status =
                    markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
                Log.d(
                    this::class.java.simpleName,
                    "App-Example-LOG %%% device credential authenticator status: $status"
                )
            }

            "CAN_AUTHENTICATE_USING_BIOMETRIC" -> {
                val canAuthenticate =
                    markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.BIOMETRIC)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using biometric: $canAuthenticate"
                )
            }

            "CAN_AUTHENTICATE_USING_DEVICE_CREDENTIAL" -> {
                val canAuthenticate =
                    markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using device credential: $canAuthenticate"
                )
            }

            "PROMPT_WEAK_BIOMETRIC" -> {
                markAuthenticator.authenticateBiometric(
                    title = "Title - Weak Biometric",
                    description = "Desc - Weak Biometric",
                    subTitle = "SubTitle - Weak Biometric",
                    negativeText = "Negative Text",
                    confirmationRequired = true,
                    callBack = object : AuthenticationCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Success authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onFailedAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Failed authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onCanceled() {
                            super.onCanceled()
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Cancel authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onNegativeButtonClicked(which: Int) {
                            super.onNegativeButtonClicked(which)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Negative Button Clicked authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_CREDENTIAL_BIOMETRIC" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    markAuthenticator.authenticateDeviceCredential(
                        title = "Title - Device Credential",
                        subTitle = "Sub Title - Device Credential",
                        description = "Desc - Device Credential",
                        negativeText = "Negative Text",
                        confirmationRequired = true,
                        callBack = object : AuthenticationCallBack {
                            override fun onSuccessAuthenticate() {
                                val toast = Toast.makeText(
                                    this@MainActivity,
                                    "Success authenticate",
                                    Toast.LENGTH_SHORT
                                )
                                toast.show()
                            }

                            override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                                val toast = Toast.makeText(
                                    this@MainActivity,
                                    "Error Authentication: ${exception.code}",
                                    Toast.LENGTH_SHORT
                                )
                                toast.show()
                            }

                            override fun onFailedAuthenticate() {
                                val toast = Toast.makeText(
                                    this@MainActivity,
                                    "Failed authenticate",
                                    Toast.LENGTH_SHORT
                                )
                                toast.show()
                            }

                            override fun onCanceled() {
                                super.onCanceled()
                                val toast = Toast.makeText(
                                    this@MainActivity,
                                    "Cancel authenticate",
                                    Toast.LENGTH_SHORT
                                )
                                toast.show()
                            }
                        }
                    )
                }
            }

            "IS_BIOMETRIC_CHANGED" -> {
                val isBiometricChanged = markAuthenticator.isBiometricChanged("fadlurahmanfdev")
                Log.d(
                    this::class.java.simpleName,
                    "App-Example-LOG %%% is biometric changed: $isBiometricChanged"
                )
            }

            "DELETE_SECRET_KEY" -> {
                markAuthenticator.deleteSecretKey("fadlurahmanfdev")
            }

            "PROMPT_ENCRYPT_BIOMETRIC" -> {
                markAuthenticator.secureAuthenticateBiometricEncrypt(
                    title = "Title - Encrypt Biometric",
                    subTitle = "Sub Title - Encrypt Biometric",
                    description = "Desc - Encrypt Biometric",
                    negativeText = "Cancel",
                    alias = "fadlurahmanfdev",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationEncryptCallBack {
                        override fun onSuccessAuthenticate(
                            cipher: Cipher,
                            encodedIVKey: String
                        ) {
                            encodedEncryptedPassword = markAuthenticator.encrypt(cipher, plainText)
                            this@MainActivity.encodedIvKey = encodedIVKey
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded iv key: ${this@MainActivity.encodedIvKey}"
                            )
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded encrypted password: $encodedEncryptedPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Encrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onFailedAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Failed authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onNegativeButtonClicked(which: Int) {
                            super.onNegativeButtonClicked(which)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Negative Button Clicked authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_DECRYPT_BIOMETRIC" -> {
                markAuthenticator.secureAuthenticateBiometricDecrypt(
                    alias = "fadlurahmanfdev",
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
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "decrypted password: $plainPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Decrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onFailedAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Failed authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onNegativeButtonClicked(which: Int) {
                            super.onNegativeButtonClicked(which)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Negative Button Clicked authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_ENCRYPT_BIOMETRIC_WITH_CUSTOM_PARAMETER" -> {
                markAuthenticator.secureAuthenticateBiometricEncrypt(
                    title = "Title - Encrypt Biometric",
                    subTitle = "Sub Title - Encrypt Biometric",
                    cipher = MarkAuthenticatorUtils.cipher(),
                    secretKey = MarkAuthenticatorUtils.getSecretKey(alias = "fadlurahmanfdev")!!,
                    description = "Desc - Encrypt Biometric",
                    negativeText = "Cancel",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationEncryptCallBack {
                        override fun onSuccessAuthenticate(
                            cipher: Cipher,
                            encodedIVKey: String
                        ) {
                            encodedEncryptedPassword = markAuthenticator.encrypt(cipher, plainText)
                            this@MainActivity.encodedIvKey = encodedIVKey
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded iv key: ${this@MainActivity.encodedIvKey}"
                            )
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded encrypted password: $encodedEncryptedPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Encrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onFailedAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Failed authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onNegativeButtonClicked(which: Int) {
                            super.onNegativeButtonClicked(which)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Negative Button Clicked authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_DECRYPT_BIOMETRIC_WITH_CUSTOM_PARAMETER" -> {
                markAuthenticator.secureAuthenticateBiometricDecrypt(
                    encodedIVKey = encodedIvKey,
                    cipher = MarkAuthenticatorUtils.cipher(),
                    secretKey = MarkAuthenticatorUtils.getSecretKey(alias = "fadlurahmanfdev")!!,
                    title = "Title - Decrypt Biometric",
                    subTitle = "Sub Title - Decrypt Biometric",
                    description = "Desc - Decrypt Biometric",
                    negativeText = "Cancel",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationDecryptCallBack {
                        override fun onSuccessAuthenticate(cipher: Cipher) {
                            val plainPassword =
                                markAuthenticator.decrypt(cipher, encodedEncryptedPassword)
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "decrypted password: $plainPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Decrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onFailedAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Failed authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onNegativeButtonClicked(which: Int) {
                            super.onNegativeButtonClicked(which)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Negative Button Clicked authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }
        }
    }
}