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

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
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

    /**
     * Clears global HTTP proxy settings and tears down cap-redir/iptables ONLY
     * when VPN mode is active, a stale cap-redir marker exists, or rootless
     * Settings.Global cleanup failed (preventing unnecessary su/Magisk prompts
     * on normal Wi-Fi proxy cleanup).
     */
    public static boolean cleanup(Context ctx, String mode, String redirPort) {
        boolean cleared = clearGlobalProxy(ctx);
        boolean rootCleaned = false;

        boolean needVpnRoot = "vpn".equalsIgnoreCase(mode) || hasStaleVpnMarker();
        boolean needSettingsRoot = !cleared;
        if ((needVpnRoot || needSettingsRoot) && isSuAvailable()) {
            rootCleaned = cleanupRootVpnAndProxy(redirPort, needSettingsRoot);
            if (needSettingsRoot && rootCleaned) {
                cleared = getGlobalHttpProxy(ctx).isEmpty();
            }
        }

        return needVpnRoot ? (cleared && rootCleaned) : cleared;
    }

    public static boolean clearGlobalProxy(Context ctx) {
        ContentResolver cr = ctx.getContentResolver();
        try {
            // Setting ":0" immediately signals ConnectivityService to drop the active proxy.
            Settings.Global.putString(cr, Settings.Global.HTTP_PROXY, ":0");
            Settings.Global.putString(cr, "global_http_proxy_host", null);
            Settings.Global.putString(cr, "global_http_proxy_port", null);
            Settings.Global.putString(cr, "global_http_proxy_exclusion_list", null);
            // Reset HTTP_PROXY to null so Android reports clean unset state instead of ":0".
            Settings.Global.putString(cr, Settings.Global.HTTP_PROXY, null);
            return getGlobalHttpProxy(ctx).isEmpty();
        } catch (SecurityException se) {
            Log.w(TAG, "Missing WRITE_SECURE_SETTINGS permission", se);
            return false;
        } catch (Throwable t) {
            Log.e(TAG, "Failed clearing global proxy via Settings.Global", t);
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

    private static boolean cleanupRootVpnAndProxy(String redirPort, boolean alsoClearSettings) {
        String sanitizedPort = sanitizePort(redirPort);
        StringBuilder script = new StringBuilder();
        if (alsoClearSettings) {
            script.append("settings put global http_proxy :0 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_host 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_port 2>/dev/null || true; ");
            script.append("settings delete global global_http_proxy_exclusion_list 2>/dev/null || true; ");
            script.append("settings delete global http_proxy 2>/dev/null || true; ");
        }
        script.append("pkill -f cap-redir 2>/dev/null || true; ");
        script.append("rm -f ").append(REDIR_PORT_FILE).append(" 2>/dev/null || true; ");
        appendIptablesCleanup(script, sanitizedPort);
        if (!"9999".equals(sanitizedPort)) {
            appendIptablesCleanup(script, "9999");
        }
        return runSuCommand(script.toString());
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
        Process proc = null;
        try {
            proc = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            final InputStream is = proc.getInputStream();
            Thread drainer = new Thread(new Runnable() {
                @Override
                public void run() {
                    byte[] buf = new byte[1024];
                    try {
                        while (is.read(buf) != -1) {
                            // discard output so child never blocks on full pipe buffer
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }, "cap-su-drain");
            drainer.setDaemon(true);
            drainer.start();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                boolean finished = proc.waitFor(SU_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                if (!finished) {
                    Log.w(TAG, "su command timed out after " + SU_TIMEOUT_SECONDS + "s");
                    proc.destroyForcibly();
                    return false;
                }
                return proc.exitValue() == 0;
            }
            int code = proc.waitFor();
            return code == 0;
        } catch (Throwable t) {
            Log.d(TAG, "su command unavailable or failed: " + t.getMessage());
            return false;
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
