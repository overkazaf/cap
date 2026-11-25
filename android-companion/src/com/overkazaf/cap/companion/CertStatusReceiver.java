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
    private static final int MAX_CERT_B64_CHARS = 65536;
    private static final int MAX_CERT_BYTES = 48 * 1024;

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
        boolean isCheck = ACTION_CHECK_CERT.equals(action);
        boolean isSync = ACTION_SYNC_CERT.equals(action);
        if (!isCheck && !isSync) {
            return;
        }

        String expectedHash = CertInspector.normalizeHash(intent.getStringExtra(EXTRA_EXPECTED_HASH));
        String expectedFp = intent.getStringExtra(EXTRA_EXPECTED_FP);
        String certPath = intent.getStringExtra(EXTRA_CERT_PATH);

        // ACTION_CHECK_CERT is strictly read-only; only ACTION_SYNC_CERT persists cert bytes/metadata.
        if (isSync) {
            String certB64 = intent.getStringExtra(EXTRA_CERT_B64);
            if (certB64 != null) {
                String trimmedB64 = certB64.trim();
                if (!trimmedB64.isEmpty() && trimmedB64.length() <= MAX_CERT_B64_CHARS) {
                    try {
                        byte[] certBytes = Base64.decode(trimmedB64, Base64.DEFAULT);
                        if (certBytes != null && certBytes.length > 0 && certBytes.length <= MAX_CERT_BYTES) {
                            X509Certificate parsed = CertInspector.parseCertBytes(certBytes);
                            if (parsed != null) {
                                ProxyCleaner.savePrivateCertBytes(context, certBytes);
                                if (expectedHash.isEmpty()) {
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
                            } else {
                                Log.w(TAG, "Ignoring invalid X.509 cert_b64 payload in ACTION_SYNC_CERT");
                            }
                        }
                    } catch (Throwable t) {
                        Log.w(TAG, "Failed decoding cert_b64 in broadcast: " + t.getMessage());
                    }
                }
            } else if (!expectedHash.isEmpty() || (expectedFp != null && !expectedFp.trim().isEmpty())) {
                GuardPrefs.saveCertMeta(context, expectedHash, expectedFp, null);
            }

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
