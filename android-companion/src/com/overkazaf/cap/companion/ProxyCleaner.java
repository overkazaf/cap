package com.overkazaf.cap.companion;

import android.Manifest;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageManager;
import android.provider.Settings;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

/**
 * Handles device-side proxy cleanup (non-rooted via WRITE_SECURE_SETTINGS and
 * rooted via su/iptables) plus lightweight TCP reachability probing.
 */
public final class ProxyCleaner {
    private static final String TAG = "CapGuardCleaner";
    public static final String DEFAULT_CERT_PATH = "/sdcard/Download/cap-ca.crt";

    private ProxyCleaner() {}

    public static boolean hasWriteSecureSettings(Context ctx) {
        return ctx.checkSelfPermission(Manifest.permission.WRITE_SECURE_SETTINGS)
                == PackageManager.PERMISSION_GRANTED;
    }

    public static String getGlobalHttpProxy(Context ctx) {
        try {
            String val = Settings.Global.getString(ctx.getContentResolver(), Settings.Global.HTTP_PROXY);
            if (val == null || val.trim().isEmpty() || ":0".equals(val.trim()) || "null".equalsIgnoreCase(val.trim())) {
                return "";
            }
            return val.trim();
        } catch (Throwable t) {
            return "";
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
     * Clears global HTTP proxy settings and (when in VPN mode or rooted) tears down
     * cap-redir and iptables REDIRECT rules.
     */
    public static boolean cleanup(Context ctx, String mode, String redirPort) {
        boolean cleared = clearGlobalProxy(ctx);
        boolean rootCleaned = false;

        boolean wantRoot = "vpn".equalsIgnoreCase(mode) || !cleared;
        if (wantRoot || isSuAvailable()) {
            rootCleaned = cleanupRootVpnAndProxy(redirPort, !cleared);
        }

        return cleared || rootCleaned;
    }

    public static boolean clearGlobalProxy(Context ctx) {
        ContentResolver cr = ctx.getContentResolver();
        try {
            // Setting ":0" immediately signals ConnectivityService to drop the proxy.
            Settings.Global.putString(cr, Settings.Global.HTTP_PROXY, ":0");
            Settings.Global.putString(cr, "global_http_proxy_host", "");
            Settings.Global.putString(cr, "global_http_proxy_port", "");
            Settings.Global.putString(cr, "global_http_proxy_exclusion_list", "");
            // Verify cleared
            String current = getGlobalHttpProxy(ctx);
            return current.isEmpty();
        } catch (SecurityException se) {
            Log.w(TAG, "Missing WRITE_SECURE_SETTINGS permission", se);
            return false;
        } catch (Throwable t) {
            Log.e(TAG, "Failed clearing global proxy via Settings.Global", t);
            return false;
        }
    }

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
            if (new File(p).exists()) {
                return true;
            }
        }
        String pathEnv = System.getenv("PATH");
        if (pathEnv != null && !pathEnv.isEmpty()) {
            for (String dir : pathEnv.split(":")) {
                if (dir != null && !dir.isEmpty() && new File(dir, "su").exists()) {
                    return true;
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
        }
        script.append("pkill -f cap-redir 2>/dev/null || true; ");
        script.append("rm -f /data/local/tmp/cap-redir.port 2>/dev/null || true; ");
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
            int code = proc.waitFor();
            return code == 0;
        } catch (Throwable t) {
            Log.d(TAG, "su cleanup unavailable or failed: " + t.getMessage());
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
            if (f.isFile() && f.canRead()) {
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
}
