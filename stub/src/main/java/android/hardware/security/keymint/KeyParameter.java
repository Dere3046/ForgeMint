package android.hardware.security.keymint;

import android.os.Parcel;
import android.os.Parcelable;

public class KeyParameter implements Parcelable {
    public int tag;
    public KeyParameterValue value;

    public static final Parcelable.Creator<KeyParameter> CREATOR =
            new Parcelable.Creator<>() {
                public KeyParameter createFromParcel(Parcel in) {
                    return new KeyParameter();
                }
                public KeyParameter[] newArray(int size) {
                    return new KeyParameter[size];
                }
            };

    @Override
    public int describeContents() { return 0; }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        throw new UnsupportedOperationException("STUB!");
    }
}
