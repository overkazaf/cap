package com.overkazaf.cap.companion;

import android.Manifest;
import android.app.NotificationManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

/**
 * Handles device-side proxy inspection and cleanup (non-rooted via
 * WRITE_SECURE_SETTINGS and rooted via su/iptables), permission/environment
 * checks, and lightweight TCP reachability probing.
 */
public final class ProxyCleaner {
    private static final String TAG = "CapGuardCleaner";
    public static final String DEFAULT_CERT_PATH = "/sdcard/Download/cap-ca.crt";
    public static final String REDIR_PORT_FILE = "/data/local/tmp/cap-redir.port";
    private static final long SU_TIMEOUT_SECONDS = 8L;

    private ProxyCleaner() {}

    public static final class HostPort {
        public final String host;
        public final int port;

        public HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    public static boolean hasWriteSecureSettings(Context ctx) {
        return ctx.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS)
                == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean isBatteryOptimizationIgnored(Context ctx) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        try {
            PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            return pm != null && pm.isIgnoringBatteryOptimizations(ctx.getPackageName());
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean areNotificationsEnabled(Context ctx) {
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                if (ctx.checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                        != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            return nm == null || nm.areNotificationsEnabled();
        } catch (Throwable t) {
            return true;
        }
    }

    /**
     * Reads the active Android global HTTP proxy from Settings.Global.
     * Treats null, "", ":0", ":", "0", and "null" as unset, and also checks
     * auxiliary global_http_proxy_host/port keys so stale proxy state is never hidden.
     */
    public static String getGlobalHttpProxy(Context ctx) {
        try {
            ContentResolver cr = ctx.getContentResolver();
            String val = normalizeProxyValue(Settings.Global.getString(cr, Settings.Global.HTTP_PROXY));
            if (!val.isEmpty()) {
                return val;
            }
            String auxHost = normalizeProxyValue(Settings.Global.getString(cr, "global_http_proxy_host"));
            if (!auxHost.isEmpty()) {
                String auxPort = normalizeProxyValue(Settings.Global.getString(cr, "global_http_proxy_port"));
                if (!auxPort.isEmpty() && !"0".equals(auxPort)) {
                    return auxHost + ":" + auxPort;
                }
                return auxHost;
            }
            return "";
        } catch (Throwable t) {
            return "";
        }
    }

    public static String normalizeProxyValue(String raw) {
        if (raw == null) {
            return "";
        }
        String v = raw.trim();
        if (v.isEmpty()
                || ":0".equals(v)
                || ":".equals(v)
                || "0".equals(v)
                || "null".equalsIgnoreCase(v)) {
            return "";
        }
        return v;
    }

    public static HostPort parseProxyHostPort(String proxyAddr) {
        String clean = normalizeProxyValue(proxyAddr);
        if (clean.isEmpty()) {
            return null;
        }
        int colon = clean.lastIndexOf(':');
        if (colon <= 0 || colon >= clean.length() - 1) {
            return null;
        }
        String host = clean.substring(0, colon).trim();
        if (host.startsWith("[") && host.endsWith("]") && host.length() > 2) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.isEmpty()) {
            return null;
        }
        try {
            int port = Integer.parseInt(clean.substring(colon + 1).trim());
            if (port <= 0 || port > 65535) {
                return null;
            }
            return new HostPort(host, port);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    public static boolean hasStaleVpnMarker() {
        try {
            return new File(REDIR_PORT_FILE).isFile();
        } catch (Throwable ignored) {
            return false;
        }
    }

    /**
     * Direct TCP reachability probe bypassing any configured system HTTP proxy.
     */
    public static boolean isProxyReachable(String host, int port, int timeoutMs) {
        if (host == null || host.trim().isEmpty() || port <= 0 || port > 65535) {
            return false;
        }
        Socket socket = null;
        try {
            socket = new Socket(Proxy.NO_PROXY);
            socket.connect(new InetSocketAddress(host.trim(), port), timeoutMs);
            return true;
        } catch (Throwable t) {
            return false;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public static final class CleanupResult {
        public static final int REASON_NONE = 0;
        public static final int REASON_NO_SECURE_SETTINGS = 1;
        public static final int REASON_NO_ROOT = 2;
        public static final int REASON_SU_DENIED = 3;
        public static final int REASON_SU_TIMEOUT = 4;
        public static final int REASON_SU_ERROR = 5;
        public static final int REASON_PROXY_REMAINED = 6;
        public static final int REASON_VPN_REMAINED = 7;

        public final boolean ok;
        public final int reasonCode;
        public final int suExitCode;
        public final String detail;

        public CleanupResult(boolean ok, int reasonCode, int suExitCode, String detail) {
            this.ok = ok;
            this.reasonCode = reasonCode;
            this.suExitCode = suExitCode;
            this.detail = detail == null ? "" : detail;
        }

        public static CleanupResult success() {
            return new CleanupResult(true, REASON_NONE, 0, "");
        }

        public String formatFailureMessage(Context ctx) {
            if (ok) {
                return ctx.getString(R.string.toast_cleaned);
            }
            switch (reasonCode) {
                case REASON_NO_SECURE_SETTINGS:
                    return ctx.getString(R.string.toast_clean_failed_perm);
                case REASON_NO_ROOT:
                    return ctx.getString(R.string.toast_clean_failed_no_root);
                case REASON_SU_DENIED:
                    return ctx.getString(R.string.toast_clean_failed_su_denied);
                case REASON_SU_TIMEOUT:
                    return ctx.getString(R.string.toast_clean_failed_su_timeout);
                case REASON_SU_ERROR: {
                    String info = detail.isEmpty() ? ("su exit " + suExitCode) : ("su exit " + suExitCode + " (" + detail + ")");
                    return ctx.getString(R.string.toast_clean_failed_detail, info);
                }
                case REASON_PROXY_REMAINED:
                case REASON_VPN_REMAINED: {
                    if (!detail.isEmpty()) {
                        return ctx.getString(R.string.toast_clean_failed_detail, detail);
                    }
                    return ctx.getString(R.string.toast_clean_failed);
                }
                default:
                    if (!detail.isEmpty()) {
                        return ctx.getString(R.string.toast_clean_failed_detail, detail);
                    }
                    return ctx.getString(R.string.toast_clean_failed);
            }
        }
    }

    private static final class SuResult {
        final boolean ok;
        final boolean timedOut;
        final int exitCode;
        final String output;

        SuResult(boolean ok, boolean timedOut, int exitCode, String output) {
            this.ok = ok;
            this.timedOut = timedOut;
            this.exitCode = exitCode;
            this.output = output == null ? "" : output.trim();
        }

        boolean isDenied() {
            if (ok || timedOut) {
                return false;
            }
            String lower = output.toLowerCase(Locale.US);
            return exitCode == 13
                    || lower.contains("permission denied")
                    || lower.contains("not allowed")
                    || lower.contains("denied");
        }
    }

    /**
     * Clears global HTTP proxy settings and tears down cap-redir/iptables ONLY
     * when VPN mode is active, a stale cap-redir marker exists, or rootless
     * Settings.Global cleanup failed (preventing unnecessary su/Magisk prompts
     * on normal Wi-Fi proxy cleanup).
     */
    public static boolean cleanup(Context ctx, String mode, String redirPort) {
        return cleanupDetailed(ctx, mode, redirPort).ok;
    }

    public static CleanupResult cleanupDetailed(Context ctx, String mode, String redirPort) {
        boolean hadGlobalProxy = !getGlobalHttpProxy(ctx).isEmpty();
        boolean cleared = clearGlobalProxy(ctx);
        boolean needVpnRoot = "vpn".equalsIgnoreCase(mode) || hasStaleVpnMarker();
        boolean needSettingsRoot = !cleared;

        if (!needVpnRoot && !needSettingsRoot) {
            return CleanupResult.success();
        }

        if (!isSuAvailable()) {
            if (needVpnRoot) {
                Log.w(TAG, "Cannot clear VPN/iptables rules: su binary not found");
                return new CleanupResult(false, CleanupResult.REASON_NO_ROOT, -1, "");
            }
            if (!hasWriteSecureSettings(ctx)) {
                return new CleanupResult(false, CleanupResult.REASON_NO_SECURE_SETTINGS, -1, "");
            }
            return new CleanupResult(
                    false,
                    CleanupResult.REASON_PROXY_REMAINED,
                    -1,
                    hadGlobalProxy ? "Settings.Global write rejected" : "");
        }

        SuResult suRes = cleanupRootVpnAndProxy(redirPort, needSettingsRoot);
        if (needSettingsRoot && suRes.ok) {
            cleared = getGlobalHttpProxy(ctx).isEmpty();
        }

        boolean vpnMarkerRemaining = needVpnRoot && hasStaleVpnMarker();
        if (suRes.ok && cleared && !vpnMarkerRemaining) {
            return CleanupResult.success();
        }

        if (suRes.timedOut) {
            return new CleanupResult(false, CleanupResult.REASON_SU_TIMEOUT, suRes.exitCode, suRes.output);
        }
        if (suRes.isDenied()) {
            return new CleanupResult(false, CleanupResult.REASON_SU_DENIED, suRes.exitCode, suRes.output);
        }
        if (!suRes.ok) {
            String shortOut = suRes.output;
            if (shortOut.length() > 120) {
                shortOut = shortOut.substring(0, 120);
            }
            return new CleanupResult(false, CleanupResult.REASON_SU_ERROR, suRes.exitCode, shortOut);
        }
        if (vpnMarkerRemaining) {
            return new CleanupResult(false, CleanupResult.REASON_VPN_REMAINED, 0, "cap-redir.port still present");
        }
        if (!cleared) {
            if (!hasWriteSecureSettings(ctx)) {
                return new CleanupResult(false, CleanupResult.REASON_NO_SECURE_SETTINGS, 0, "");
            }
            return new CleanupResult(false, CleanupResult.REASON_PROXY_REMAINED, 0, "http_proxy=" + getGlobalHttpProxy(ctx));
        }
        return CleanupResult.success();
    }

    public static boolean clearGlobalProxy(Context ctx) {
        ContentResolver cr = ctx.getContentResolver();
        boolean hadProxy = !getGlobalHttpProxy(ctx).isEmpty();
        if (!hadProxy && !hasWriteSecureSettings(ctx)) {
            // Global proxy is already unset; avoid throwing SecurityException during VPN-only cleanup.
            return true;
        }

        boolean primaryOk = false;
        SecurityException primarySecErr = null;
        try {
            // Setting ":0" immediately signals ConnectivityService to drop the active proxy.
            primaryOk = Settings.Global.putString(cr, Settings.Global.HTTP_PROXY, ":0");
        } catch (SecurityException se) {
            primarySecErr = se;
            Log.w(TAG, "Missing WRITE_SECURE_SETTINGS permission while writing http_proxy=:0", se);
        } catch (Throwable t) {
            Log.w(TAG, "Failed writing http_proxy=:0: " + t.getMessage(), t);
        }

        // Clear auxiliary keys independently so OEM SettingsProvider quirks never abort HTTP_PROXY cleanup.
        clearSingleGlobalKey(cr, "global_http_proxy_host");
        clearSingleGlobalKey(cr, "global_http_proxy_port");
        clearSingleGlobalKey(cr, "global_http_proxy_exclusion_list");

        // Reset HTTP_PROXY to null (or "" / delete) so Android reports clean unset state instead of ":0".
        boolean resetOk = clearSingleGlobalKey(cr, Settings.Global.HTTP_PROXY);
        if (!resetOk && !getGlobalHttpProxy(ctx).isEmpty()) {
            try {
                Settings.Global.putString(cr, Settings.Global.HTTP_PROXY, ":0");
            } catch (Throwable ignored) {
            }
        }

        boolean emptyNow = getGlobalHttpProxy(ctx).isEmpty();
        if (!emptyNow && primarySecErr != null) {
            Log.w(TAG, "Global proxy still active after SecurityException: " + getGlobalHttpProxy(ctx));
            return false;
        }
        if (!emptyNow && !primaryOk) {
            Log.w(TAG, "Global proxy remained set after Settings.Global cleanup: " + getGlobalHttpProxy(ctx));
        }
        return emptyNow;
    }

    private static boolean clearSingleGlobalKey(ContentResolver cr, String key) {
        try {
            if (Settings.Global.putString(cr, key, null)) {
                return true;
            }
        } catch (SecurityException se) {
            Log.w(TAG, "SecurityException clearing global setting " + key + ": " + se.getMessage());
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "putString(" + key + ", null) failed: " + t.getMessage());
        }
        try {
            if (Settings.Global.putString(cr, key, "")) {
                return true;
            }
        } catch (SecurityException se) {
            return false;
        } catch (Throwable t) {
            Log.w(TAG, "putString(" + key + ", \"\") failed: " + t.getMessage());
        }
        try {
            int deleted = cr.delete(Settings.Global.CONTENT_URI, "name=?", new String[]{key});
            return deleted >= 0;
        } catch (Throwable t) {
            Log.w(TAG, "ContentResolver.delete(" + key + ") failed: " + t.getMessage());
            return false;
        }
    }

    public static boolean grantWriteSecureSettingsViaRoot(Context ctx) {
        if (ctx == null || !isSuAvailable()) {
            return false;
        }
        String pkg = ctx.getPackageName();
        runSuCommand("pm grant " + pkg + " android.permission.WRITE_SECURE_SETTINGS");
        return hasWriteSecureSettings(ctx);
    }

    /**
     * Pure filesystem/PATH check for a su binary — NEVER spawns `su`, so it
     * cannot block the UI or spam Magisk superuser toasts.
     */
    public static boolean isSuAvailable() {
        String[] paths = {
                "/system/bin/su",
                "/system/xbin/su",
                "/system_ext/bin/su",
                "/debug_ramdisk/su",
                "/vendor/bin/su",
                "/product/bin/su",
                "/odm/bin/su",
                "/sbin/su",
                "/su/bin/su",
                "/data/adb/magisk/su",
                "/data/adb/ksu/bin/su",
                "/data/adb/ap/bin/su"
        };
        for (String p : paths) {
            try {
                if (new File(p).exists()) {
                    return true;
                }
            } catch (Throwable ignored) {
            }
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null && !pathEnv.isEmpty()) {
            for (String dir : pathEnv.split(":")) {
                if (dir != null && !dir.isEmpty()) {
                    try {
                        if (new File(dir, "su").exists()) {
                            return true;
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        }
        return false;
    }

    private static SuResult cleanupRootVpnAndProxy(String redirPort, boolean alsoClearSettings) {
        String sanitizedPort = sanitizePort(redirPort);
        StringBuilder script = new StringBuilder();
        // Read any recorded port before removing the marker file.
        script.append("RP=$(cat ").append(REDIR_PORT_FILE).append(" 2>/dev/null | tr -cd '0-9'); ");
        if (alsoClearSettings) {
            script.append("settings put global http_proxy :0 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_host 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_port 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_exclusion_list 2>/dev/null || true; ");
            script.append("settings delete global http_proxy 2>/dev/null || true; ");
        }
        // IMPORTANT: NEVER use `pkill -f cap-redir` here! Because this script runs via
        // `su -c "<script>"` and references `/data/local/tmp/cap-redir.port`, `pkill -f`
        // matches the parent `sh -c` / `su -c` cmdline and terminates itself (exit 143)
        // before `rm -f` and `iptables -D` ever execute. Match exact process name only.
        script.append("pkill -x cap-redir 2>/dev/null || killall cap-redir 2>/dev/null || true; ");
        script.append("for p in $(pidof cap-redir 2>/dev/null); do kill \"$p\" 2>/dev/null || true; done; ");
        script.append("rm -f ").append(REDIR_PORT_FILE).append(" 2>/dev/null || true; ");
        appendIptablesCleanup(script, sanitizedPort);
        if (!"9999".equals(sanitizedPort)) {
            appendIptablesCleanup(script, "9999");
        }
        // Also flush recorded port if it differs from both sanitizedPort and 9999.
        script.append("if [ -n \"$RP\" ] && [ \"$RP\" != \"").append(sanitizedPort).append("\" ] && [ \"$RP\" != \"9999\" ]; then ");
        appendIptablesCleanup(script, "$RP");
        script.append("fi; ");
        script.append("true");
        return runSuCommandDetailed(script.toString());
    }

    private static void appendIptablesCleanup(StringBuilder sb, String port) {
        sb.append("while iptables -t nat -D OUTPUT -p tcp --dport 80 -j REDIRECT --to-port ")
                .append(port).append(" 2>/dev/null; do :; done; ");
        sb.append("while iptables -t nat -D OUTPUT -p tcp --dport 443 -j REDIRECT --to-port ")
                .append(port).append(" 2>/dev/null; do :; done; ");
    }

    private static String sanitizePort(String port) {
        if (port == null || port.isEmpty()) {
            return "9999";
        }
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < port.length(); i++) {
            char c = port.charAt(i);
            if (c >= '0' && c <= '9') {
                digits.append(c);
            }
        }
        return digits.length() > 0 ? digits.toString() : "9999";
    }

    private static boolean runSuCommand(String cmd) {
        return runSuCommandDetailed(cmd).ok;
    }

    private static SuResult runSuCommandDetailed(String cmd) {
        Process proc = null;
        try {
            proc = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            final InputStream is = proc.getInputStream();
            final ByteArrayOutputStream captured = new ByteArrayOutputStream();
            final int maxCapture = 2048;
            Thread drainer = new Thread(new Runnable() {
                @Override
                public void run() {
                    byte[] buf = new byte[1024];
                    int total = 0;
                    try {
                        int n;
                        while ((n = is.read(buf)) != -1) {
                            if (total < maxCapture) {
                                int toWrite = Math.min(n, maxCapture - total);
                                captured.write(buf, 0, toWrite);
                                total += toWrite;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }, "cap-su-drain");
            drainer.setDaemon(true);
            drainer.start();

            int code;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                boolean finished = proc.waitFor(SU_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                if (!finished) {
                    Log.w(TAG, "su command timed out after " + SU_TIMEOUT_SECONDS + "s");
                    proc.destroyForcibly();
                    try {
                        drainer.join(200);
                    } catch (InterruptedException ignored) {
                    }
                    return new SuResult(false, true, -1, new String(captured.toByteArray(), "UTF-8"));
                }
                code = proc.exitValue();
            } else {
                code = proc.waitFor();
            }
            try {
                drainer.join(500);
            } catch (InterruptedException ignored) {
            }
            String out = new String(captured.toByteArray(), "UTF-8").trim();
            if (code != 0) {
                Log.w(TAG, "su command failed with exit=" + code + (out.isEmpty() ? "" : (" output=" + out)));
            }
            return new SuResult(code == 0, false, code, out);
        } catch (Throwable t) {
            String msg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            Log.w(TAG, "su command unavailable or failed: " + msg);
            return new SuResult(false, false, -1, msg);
        } finally {
            if (proc != null) {
                try {
                    proc.destroy();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public static File savePrivateCertBytes(Context ctx, byte[] certBytes) {
        if (ctx == null || certBytes == null || certBytes.length == 0) {
            return null;
        }
        File out = new File(ctx.getApplicationContext().getFilesDir(), "cap-ca.crt");
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(out, false);
            fos.write(certBytes);
            fos.flush();
            return out;
        } catch (Throwable t) {
            Log.w(TAG, "Failed caching CA cert into app-private storage: " + t.getMessage());
            return null;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    public static File findCertFile(Context ctx, String preferredPath) {
        if (preferredPath != null && !preferredPath.trim().isEmpty()) {
            File f = new File(preferredPath.trim());
            if (isAllowedCertPath(ctx, f) && f.isFile() && f.canRead()) {
                return f;
            }
        }
        if (ctx != null) {
            File privateCert = new File(ctx.getApplicationContext().getFilesDir(), "cap-ca.crt");
            if (privateCert.isFile() && privateCert.canRead()) {
                return privateCert;
            }
            File extDir = ctx.getExternalFilesDir(null);
            if (extDir != null) {
                File appCert = new File(extDir, "cap-ca.crt");
                if (appCert.isFile() && appCert.canRead()) {
                    return appCert;
                }
            }
        }
        File download = new File(DEFAULT_CERT_PATH);
        if (download.isFile() && download.canRead()) {
            return download;
        }
        File tmp = new File("/data/local/tmp/cap-ca.crt");
        if (tmp.isFile() && tmp.canRead()) {
            return tmp;
        }
        return null;
    }

    public static boolean isAllowedCertPath(Context ctx, File candidate) {
        if (candidate == null) {
            return false;
        }
        String lowerName = candidate.getName().toLowerCase(java.util.Locale.US);
        if (!lowerName.endsWith(".crt")
                && !lowerName.endsWith(".cer")
                && !lowerName.endsWith(".pem")
                && !lowerName.endsWith(".der")) {
            return false;
        }
        try {
            String canonical = candidate.getCanonicalPath();
            java.util.ArrayList<File> allowedDirs = new java.util.ArrayList<File>();
            if (ctx != null) {
                File filesDir = ctx.getApplicationContext().getFilesDir();
                if (filesDir != null) {
                    allowedDirs.add(filesDir);
                }
                File extDir = ctx.getExternalFilesDir(null);
                if (extDir != null) {
                    allowedDirs.add(extDir);
                }
            }
            allowedDirs.add(new File("/sdcard/Download"));
            allowedDirs.add(new File("/storage/emulated/0/Download"));
            allowedDirs.add(new File("/data/local/tmp"));

            for (File dir : allowedDirs) {
                try {
                    String dirCanon = dir.getCanonicalPath();
                    String prefix = dirCanon.endsWith(File.separator) ? dirCanon : dirCanon + File.separator;
                    if (canonical.startsWith(prefix)) {
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
            return false;
        }
        return false;
    }
}
