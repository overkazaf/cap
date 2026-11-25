package com.overkazaf.cap.companion;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Persists active guard session state and last cleanup metadata across
 * process restarts and device reboots.
 */
public final class GuardPrefs {
    private static final String PREFS_NAME = "cap_guard_prefs";

    private static final String KEY_ACTIVE = "active";
    private static final String KEY_PROXY_HOST = "proxy_host";
    private static final String KEY_PROXY_PORT = "proxy_port";
    private static final String KEY_MODE = "mode";
    private static final String KEY_REDIR_PORT = "redir_port";
    private static final String KEY_HEARTBEAT_MS = "heartbeat_ms";
    private static final String KEY_MISS_THRESHOLD = "miss_threshold";
    private static final String KEY_MISS_COUNT = "miss_count";
    private static final String KEY_LAST_CLEANUP_TS = "last_cleanup_ts";
    private static final String KEY_LAST_CLEANUP_REASON = "last_cleanup_reason";
    private static final String KEY_LAST_CLEANUP_OK = "last_cleanup_ok";
    private static final String KEY_CERT_HASH = "cert_hash";
    private static final String KEY_CERT_FP = "cert_fp";
    private static final String KEY_CERT_SUBJECT = "cert_subject";

    private GuardPrefs() {}

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static void saveSession(
            Context ctx,
            String host,
            int port,
            String mode,
            String redirPort,
            int heartbeatMs,
            int missThreshold) {
        prefs(ctx).edit()
                .putBoolean(KEY_ACTIVE, true)
                .putString(KEY_PROXY_HOST, host == null ? "" : host)
                .putInt(KEY_PROXY_PORT, port)
                .putString(KEY_MODE, mode == null || mode.isEmpty() ? "proxy" : mode)
                .putString(KEY_REDIR_PORT, redirPort == null || redirPort.isEmpty() ? "9999" : redirPort)
                .putInt(KEY_HEARTBEAT_MS, heartbeatMs)
                .putInt(KEY_MISS_THRESHOLD, missThreshold)
                .putInt(KEY_MISS_COUNT, 0)
                .apply();
    }

    public static void updateMissCount(Context ctx, int misses) {
        prefs(ctx).edit().putInt(KEY_MISS_COUNT, misses).apply();
    }

    public static void recordCleanup(Context ctx, String reason, boolean ok) {
        prefs(ctx).edit()
                .putBoolean(KEY_ACTIVE, false)
                .putInt(KEY_MISS_COUNT, 0)
                .putLong(KEY_LAST_CLEANUP_TS, System.currentTimeMillis())
                .putString(KEY_LAST_CLEANUP_REASON, reason == null ? "" : reason)
                .putBoolean(KEY_LAST_CLEANUP_OK, ok)
                .apply();
    }

    public static boolean isActive(Context ctx) {
        return prefs(ctx).getBoolean(KEY_ACTIVE, false);
    }

    public static String getProxyHost(Context ctx) {
        return prefs(ctx).getString(KEY_PROXY_HOST, "");
    }

    public static int getProxyPort(Context ctx) {
        return prefs(ctx).getInt(KEY_PROXY_PORT, 8080);
    }

    public static String getMode(Context ctx) {
        return prefs(ctx).getString(KEY_MODE, "proxy");
    }

    public static String getRedirPort(Context ctx) {
        return prefs(ctx).getString(KEY_REDIR_PORT, "9999");
    }

    public static int getHeartbeatMs(Context ctx) {
        return prefs(ctx).getInt(KEY_HEARTBEAT_MS, 3000);
    }

    public static int getMissThreshold(Context ctx) {
        return prefs(ctx).getInt(KEY_MISS_THRESHOLD, 3);
    }

    public static int getMissCount(Context ctx) {
        return prefs(ctx).getInt(KEY_MISS_COUNT, 0);
    }

    public static long getLastCleanupTs(Context ctx) {
        return prefs(ctx).getLong(KEY_LAST_CLEANUP_TS, 0L);
    }

    public static String getLastCleanupReason(Context ctx) {
        return prefs(ctx).getString(KEY_LAST_CLEANUP_REASON, "");
    }

    public static boolean getLastCleanupOk(Context ctx) {
        return prefs(ctx).getBoolean(KEY_LAST_CLEANUP_OK, false);
    }

    public static void saveCertMeta(Context ctx, String hash, String fingerprint, String subject) {
        SharedPreferences.Editor ed = prefs(ctx).edit();
        if (hash != null && !hash.trim().isEmpty()) {
            ed.putString(KEY_CERT_HASH, hash.trim());
        }
        if (fingerprint != null && !fingerprint.trim().isEmpty()) {
            ed.putString(KEY_CERT_FP, fingerprint.trim());
        }
        if (subject != null && !subject.trim().isEmpty()) {
            ed.putString(KEY_CERT_SUBJECT, subject.trim());
        }
        ed.apply();
    }

    public static String getCertHash(Context ctx) {
        return prefs(ctx).getString(KEY_CERT_HASH, "");
    }

    public static String getCertFingerprint(Context ctx) {
        return prefs(ctx).getString(KEY_CERT_FP, "");
    }

    public static String getCertSubject(Context ctx) {
        return prefs(ctx).getString(KEY_CERT_SUBJECT, "");
    }
}
