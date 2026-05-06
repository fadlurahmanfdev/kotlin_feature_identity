package com.fadlurahmanfdev.mark_authenticator.core.enums

enum class MarkAuthenticationStatus {
    /**
     * Can authenticate using biometrics.
     */
    SUCCESS,

    /**
     * No biometric hardware available on the device.
     */
    NO_HARDWARE,

    /**
     * Biometric hardware is currently unavailable. Please check again later.
     */
    UNAVAILABLE,

    /**
     * No biometric credentials are set up.
     */
    NONE_ENROLLED,
    SECURITY_UPDATE_REQUIRED,
    UNSUPPORTED_OS_VERSION,
    UNKNOWN,
}