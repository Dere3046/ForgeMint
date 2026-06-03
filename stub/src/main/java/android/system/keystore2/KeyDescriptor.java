package android.system.keystore2;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyDescriptor implements Parcelable {
    public int domain;
    public long nspace;
    public String alias;
    public byte[] blob;

    public static final Parcelable.Creator<KeyDescriptor> CREATOR =
            new Parcelable.Creator<>() {
                public KeyDescriptor createFromParcel(Parcel in) {
                    return new KeyDescriptor();
                }
                public KeyDescriptor[] newArray(int size) {
                    return new KeyDescriptor[size];
                }
            };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
