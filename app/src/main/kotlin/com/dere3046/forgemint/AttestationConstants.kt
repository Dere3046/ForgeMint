package com.dere3046.forgemint

object AttestationConstants {
    val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    const val TAG_PURPOSE = 1
    const val TAG_ALGORITHM = 2
    const val TAG_KEY_SIZE = 3
    const val TAG_BLOCK_MODE = 4
    const val TAG_DIGEST = 5
    const val TAG_PADDING = 6
    const val TAG_EC_CURVE = 10
    const val TAG_RSA_PUBLIC_EXPONENT = 200
    const val TAG_NO_AUTH_REQUIRED = 503
    const val TAG_ORIGIN = 702
    const val TAG_CREATION_DATETIME = 701
    const val TAG_ROOT_OF_TRUST = 704
    const val TAG_OS_VERSION = 705
    const val TAG_OS_PATCHLEVEL = 706
    const val TAG_ATTESTATION_APPLICATION_ID = 709
    const val TAG_ATTESTATION_ID_BRAND = 710
    const val TAG_ATTESTATION_ID_DEVICE = 711
    const val TAG_ATTESTATION_ID_PRODUCT = 712
    const val TAG_ATTESTATION_ID_SERIAL = 713
    const val TAG_ATTESTATION_ID_IMEI = 714
    const val TAG_ATTESTATION_ID_MEID = 715
    const val TAG_ATTESTATION_ID_MANUFACTURER = 716
    const val TAG_ATTESTATION_ID_MODEL = 717
    const val TAG_VENDOR_PATCHLEVEL = 718
    const val TAG_BOOT_PATCHLEVEL = 719
    const val TAG_ATTESTATION_ID_SECOND_IMEI = 723
    const val TAG_MODULE_HASH = 724
    const val CHALLENGE_LENGTH_LIMIT = 128
}
