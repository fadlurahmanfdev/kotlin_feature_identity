package com.fadlurahmanfdev.mark_authenticator.core.callback

import com.fadlurahmanfdev.mark_authenticator.exception.MarkAuthenticatorException
import javax.crypto.Cipher

interface MarkAuthenticationCallBack {
    fun onFailedAuthenticate()

    fun onErrorAuthenticate(exception: MarkAuthenticatorException)

    fun onCanceled() {}
}

interface WeakAuthenticationCallBack : MarkAuthenticationCallBack {
    fun onSuccessAuthenticate()
}

interface SecureAuthenticationEncryptCallBack : MarkAuthenticationCallBack {
    fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String)
}

interface SecureAuthenticationDecryptCallBack : MarkAuthenticationCallBack {
    fun onSuccessAuthenticate(cipher: Cipher)
}