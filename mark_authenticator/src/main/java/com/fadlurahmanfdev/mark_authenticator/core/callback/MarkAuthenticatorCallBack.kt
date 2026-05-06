package com.fadlurahmanfdev.mark_authenticator.core.callback

import com.fadlurahmanfdev.mark_authenticator.core.exception.FeatureIdentityException
import javax.crypto.Cipher

interface MarkAuthenticatorCallBack {
    fun onNegativeButtonClicked(which: Int) {}
    fun onFailedAuthenticate()

    fun onErrorAuthenticate(exception: FeatureIdentityException)

    fun onCanceled() {}
}

interface AuthenticationCallBack : MarkAuthenticatorCallBack {
    fun onSuccessAuthenticate()
}

interface SecureAuthenticationEncryptCallBack : MarkAuthenticatorCallBack {
    fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String)
}

interface SecureAuthenticationDecryptCallBack : MarkAuthenticatorCallBack {
    fun onSuccessAuthenticate(cipher: Cipher)
}