package com.vrp.zeroperm;

import android.app.Activity;
import android.os.Bundle;
import android.security.KeyChain;
import android.util.Base64;
import android.util.Log;

// Test-setup helper only (not the exploit itself): triggers the standard
// system "Install certificate" flow with a locally-generated test CA cert,
// to put the device into a realistic state ("user has a corporate/VPN CA
// installed") so the KeychainCaLeakActivity PoC can demonstrate reading it
// back with zero permissions.
public class CertInstallHelperActivity extends Activity {
    private static final String T = "CERT_SETUP";

    // Self-signed test CA: CN=AcmeCorp Internal Root CA, O=AcmeCorpVPN-Internal
    private static final String TEST_CA_B64 =
        "MIIDgTCCAmmgAwIBAgIUFdkh4Ox65DuMiWwaDFUEvOZyX7kwDQYJKoZIhvcNAQELBQAwUDELMAkGA1UEBhMCVVMxHTAbBgNVBAoMFEFjbWVDb3JwVlBOLUludGVybmFsMSIwIAYDVQQDDBlBY21lQ29ycCBJbnRlcm5hbCBSb290IENBMB4XDTI2MDkyODIwMDQ1MloXDTI3MDkyODIwMDQ1MlowUDELMAkGA1UEBhMCVVMxHTAbBgNVBAoMFEFjbWVDb3JwVlBOLUludGVybmFsMSIwIAYDVQQDDBlBY21lQ29ycCBJbnRlcm5hbCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAjcA9VjwGrwookdwX9tVe/cqaNWmeib/RaywlZ3iz23T39mOGT2+Xu7br6biorv3OftYfLlkyWDI3UAU/LVo2vYUeofKXVtr0Svazhn+2CGH1MDinbK10FrDual2v3U+Txi7Z0UOUhRX+yS5V4pm+y50Gl9+RU7+L5QcpUIubrtxBVevrJtey7u71RFVtjBQR0DtqK39pc6z4r5V59s2EmIDl23AwWtlArf1yIEHULceSR9kQfLSPxM0DNdwoV23jMjWG6O4WsQzyXm581lDt9HFj/+pWaoyb3FB57TQtuiA6jJ69CX2NhKYHxVoK4+dDD4Q4J3zwLsBUSMa1+kHwIDAQABo1MwUTAdBgNVHQ4EFgQUCVKG9Qe3idS/BMvNt2PpnTUBEPEwHwYDVR0jBBgwFoAUCVKG9Qe3idS/BMvNt2PpnTUBEPEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAoOnZFkN/Brwwwuac/Ge2ufd3HfG9FfFPMdVzwOzBHoSTW5Uy/XqVBv6bpH3oxaGzKYpjJAUQoJUbd94jHqbUDcwcHe/2+en5DB92AIuE5ktUEdULV6bTfqh0fY9se6BhhBox++LAgQrimhuqm5Hx4jPmZbtrfNa9tSBsRAHg9HAtJc/J799KbzAFJ6qcBpNNnyW3yGdKpzAMduVf4V7+ZuZex5D9BPlGD3FpNoI42gPzGoppCnp15PLJG4P9FvtRxohj5KMtx3gtKqlYbVWfZHtk4qcz+Z9QIpeqVmJoAyNM/snp9i/hA14y6pZJQL9bt3/VIDU/0m/tzNz5rE6qrA==";

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.w(T, "Launching standard CertInstaller flow with test CA (simulates a user installing a corporate/VPN CA)");
        try {
            byte[] certBytes = Base64.decode(TEST_CA_B64, Base64.DEFAULT);
            android.content.Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, certBytes);
            installIntent.putExtra(KeyChain.EXTRA_NAME, "AcmeCorp Internal Root CA");
            startActivity(installIntent);
        } catch (Exception e) {
            Log.e(T, "Failed to launch cert install", e);
        }
        finish();
    }
}
