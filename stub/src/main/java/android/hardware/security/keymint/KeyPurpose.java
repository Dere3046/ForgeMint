package android.hardware.security.keymint;

public @interface KeyPurpose {
    int ATTEST_KEY = 7;
    int SIGN = 2;
    int DECRYPT = 3;
    int WRAP_KEY = 5;
    int AGREE_KEY = 6;
}
