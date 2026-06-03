package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.Nullable;

public class KeyMetadata implements Parcelable {
    public int keySecurityLevel;
    public KeyDescriptor key;
    public Long modificationTimeMs;
    public Authorization[] authorizations;
    @Nullable public byte[] certificate;
    @Nullable public byte[] certificateChain;

    public static final Parcelable.Creator<KeyMetadata> CREATOR =
            new Parcelable.Creator<>() {
                public KeyMetadata createFromParcel(Parcel in) {
                    return new KeyMetadata();
                }
                public KeyMetadata[] newArray(int size) {
                    return new KeyMetadata[size];
                }
            };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
