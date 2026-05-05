package com.fadlurahmanfdev.mark_biometric.core.enums

enum class FeatureAuthenticationStatus {
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