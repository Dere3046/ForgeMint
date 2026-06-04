package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyParameterValue implements Parcelable {
    public int algorithm;
    public int integer;
    public long longInteger;
    public byte[] blob;
    public boolean boolValue;
    public long dateTime;
    public int ecCurve;
    public int origin;
    public int blockMode;
    public int paddingMode;
    public int keyPurpose;
    public int digest;

    public static final Parcelable.Creator<KeyParameterValue> CREATOR =
            new Parcelable.Creator<>() {
                public KeyParameterValue createFromParcel(Parcel in) {
                    throw new UnsupportedOperationException("STUB!");
                }
                public KeyParameterValue[] newArray(int size) {
                    throw new UnsupportedOperationException("STUB!");
                }
            };

    @Override
    public int describeContents() { throw new UnsupportedOperationException("STUB!"); }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
