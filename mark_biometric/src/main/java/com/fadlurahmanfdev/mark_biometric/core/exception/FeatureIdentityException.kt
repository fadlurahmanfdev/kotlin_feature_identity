package com.fadlurahmanfdev.mark_biometric.core.exception

data class FeatureIdentityException(
    val code: String,
    override val message: String? = null,
) : Throwable(message = message)