package com.overkazaf.cap.companion;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Base64;
import android.util.Log;

import java.security.cert.X509Certificate;

/**
 * Responds to ADB-triggered ordered broadcasts from the desktop cap host so
 * host diagnostics can query Android's live AndroidCAStore without root and
 * push/sync CA certificate metadata into app-private storage (immune to
 * Android 11+ Scoped Storage restrictions).
 */
public class CertStatusReceiver extends BroadcastReceiver {
    private static final String TAG = "CapCertReceiver";

    public static final String ACTION_CHECK_CERT = "com.overkazaf.cap.companion.ACTION_CHECK_CERT";
    public static final String ACTION_SYNC_CERT = "com.overkazaf.cap.companion.ACTION_SYNC_CERT";

    public static final String EXTRA_EXPECTED_HASH = "expected_hash";
    public static final String EXTRA_EXPECTED_FP = "expected_fp";
    public static final String EXTRA_CERT_PATH = "cert_path";
    public static final String EXTRA_CERT_B64 = "cert_b64";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        String expectedHash = intent.getStringExtra(EXTRA_EXPECTED_HASH);
        String expectedFp = intent.getStringExtra(EXTRA_EXPECTED_FP);
        String certPath = intent.getStringExtra(EXTRA_CERT_PATH);
        String certB64 = intent.getStringExtra(EXTRA_CERT_B64);

        // Persist cert bytes into app-private storage if provided
        if (certB64 != null && !certB64.trim().isEmpty()) {
            try {
                byte[] certBytes = Base64.decode(certB64.trim(), Base64.DEFAULT);
                if (certBytes != null && certBytes.length > 0) {
                    ProxyCleaner.savePrivateCertBytes(context, certBytes);
                    X509Certificate parsed = CertInspector.parseCertBytes(certBytes);
                    if (parsed != null) {
                        if (expectedHash == null || expectedHash.trim().isEmpty()) {
                            expectedHash = CertInspector.computeSubjectHashOld(parsed);
                        }
                        if (expectedFp == null || expectedFp.trim().isEmpty()) {
                            expectedFp = CertInspector.computeSha256Fingerprint(parsed);
                        }
                        GuardPrefs.saveCertMeta(
                                context,
                                expectedHash,
                                expectedFp,
                                CertInspector.extractCommonName(parsed));
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "Failed decoding cert_b64 in broadcast: " + t.getMessage());
            }
        } else if ((expectedHash != null && !expectedHash.trim().isEmpty())
                || (expectedFp != null && !expectedFp.trim().isEmpty())) {
            GuardPrefs.saveCertMeta(context, expectedHash, expectedFp, null);
        }

        if (ACTION_SYNC_CERT.equals(action)) {
            Intent statusChanged = new Intent(ProxyGuardService.ACTION_STATUS_CHANGED);
            statusChanged.setPackage(context.getPackageName());
            context.sendBroadcast(statusChanged);
        }

        CertInspector.CertCheckResult res = CertInspector.inspect(context, expectedHash, expectedFp, certPath);
        if (isOrderedBroadcast()) {
            setResultCode(Activity.RESULT_OK);
            setResultData(res.toKeyValueString());
        }
    }
}
