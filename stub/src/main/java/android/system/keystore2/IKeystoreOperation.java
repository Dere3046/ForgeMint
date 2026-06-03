package android.system.keystore2;

import android.os.IBinder;
import android.os.IInterface;

public interface IKeystoreOperation extends IInterface {
    String DESCRIPTOR = "android.system.keystore2.IKeystoreOperation";

    byte[] finish(byte[] input, byte[] signature);
    int updateAad(byte[] input);
    byte[] update(byte[] input);
    void abort();

    class Stub {
        public static IKeystoreOperation asInterface(IBinder b) {
            throw new UnsupportedOperationException("STUB!");
        }
    }
}
