package android.hardware.security.keymint;

public @interface PaddingMode {
    int NONE = 1;
    int RSA_OAEP = 2;
    int RSA_PSS = 3;
    int RSA_PKCS1_1_5_ENCRYPT = 4;
    int RSA_PKCS1_1_5_SIGN = 5;
    int PKCS7 = 64;
}
