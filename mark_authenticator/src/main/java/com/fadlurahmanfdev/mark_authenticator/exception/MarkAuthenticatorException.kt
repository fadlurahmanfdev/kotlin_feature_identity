package com.fadlurahmanfdev.mark_authenticator.exception

data class MarkAuthenticatorException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
) : Throwable(message = message, cause = cause)