package com.google.android.gms.auth.api.identity;

import android.os.Parcel;
import android.os.Parcelable;

public class GetPhoneNumberHintIntentRequest implements Parcelable {
    private final int value;

    public GetPhoneNumberHintIntentRequest(int value) {
        this.value = value;
    }

    @Override
    public void writeToParcel(Parcel parcel, int flags) {
        // SafeParcel format matching GMS's exact output:
        // Begin marker: (0xFFFF << 16) | version(20293=0x4F45)
        parcel.writeInt(0xFFFF4F45);
        // Total data size: 8 bytes (1 field header + 1 int value)
        parcel.writeInt(8);
        // Field 1 header: (dataSize=4 << 16) | fieldId=1
        parcel.writeInt(0x00040001);
        // Field 1 value
        parcel.writeInt(this.value);
    }

    @Override
    public int describeContents() {
        return 0;
    }

    public static final Parcelable.Creator<GetPhoneNumberHintIntentRequest> CREATOR =
        new Parcelable.Creator<GetPhoneNumberHintIntentRequest>() {
            @Override
            public GetPhoneNumberHintIntentRequest createFromParcel(Parcel in) {
                return new GetPhoneNumberHintIntentRequest(0);
            }

            @Override
            public GetPhoneNumberHintIntentRequest[] newArray(int size) {
                return new GetPhoneNumberHintIntentRequest[size];
            }
        };
}
