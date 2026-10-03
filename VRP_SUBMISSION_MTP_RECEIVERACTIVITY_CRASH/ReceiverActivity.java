package com.android.mtp;

import android.app.Activity;
import android.content.Intent;
import android.hardware.usb.UsbDevice;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.util.Log;
import java.io.IOException;

/* loaded from: classes.dex */
public class ReceiverActivity extends Activity {
    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if ("android.hardware.usb.action.USB_DEVICE_ATTACHED".equals(getIntent().getAction())) {
            UsbDevice usbDevice = (UsbDevice) getIntent().getParcelableExtra("device");
            try {
                MtpDocumentsProvider mtpDocumentsProvider = MtpDocumentsProvider.getInstance();
                mtpDocumentsProvider.openDevice(usbDevice.getDeviceId());
                Uri uriBuildRootUri = DocumentsContract.buildRootUri("com.android.mtp.documents", mtpDocumentsProvider.getDeviceDocumentId(usbDevice.getDeviceId()));
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setDataAndType(uriBuildRootUri, "vnd.android.document/root");
                intent.addCategory("android.intent.category.DEFAULT");
                startActivity(intent);
            } catch (IOException e) {
                Log.e("MtpDocumentsProvider", "Failed to open device", e);
            }
        }
        finish();
    }
}
