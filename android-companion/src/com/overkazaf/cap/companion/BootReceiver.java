package com.overkazaf.cap.companion;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Clears stale Cap proxy settings after a device reboot (or when a running
 * Cap Guard session was interrupted by an app upgrade) if the desktop proxy is
 * no longer reachable. Never stomps unrelated user-configured proxies.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "CapGuardBoot";

    @Override
    public void onReceive(final Context context, Intent intent) {
        final String action = intent != null ? intent.getAction() : null;
        final boolean isBoot = Intent.ACTION_BOOT_COMPLETED.equals(action);
        final boolean isUpdate = Intent.ACTION_MY_PACKAGE_REPLACED.equals(action);
        if (!isBoot && !isUpdate) {
            return;
        }

        final boolean wasActive = GuardPrefs.isActive(context);
        final boolean hasStaleVpn = ProxyCleaner.hasStaleVpnMarker();
        final String currentGlobalProxy = ProxyCleaner.getGlobalHttpProxy(context);

        // On app upgrade, only recover if a Cap Guard session was actually active
        // (avoid racing with desktop SetupDetailed upgrading the APK before starting proxy).
        if (isUpdate && !wasActive) {
            return;
        }

        // On boot, only touch settings that belong to Cap: either a Cap session was active,
        // a stale cap-redir marker exists, or the global proxy matches Cap's saved host:port.
        final String savedHost = GuardPrefs.getProxyHost(context);
        final int savedPort = GuardPrefs.getProxyPort(context);
        final boolean matchesSavedCapProxy = !currentGlobalProxy.isEmpty()
                && !savedHost.isEmpty()
                && currentGlobalProxy.equals(savedHost + ":" + savedPort);

        if (!wasActive && !hasStaleVpn && !matchesSavedCapProxy) {
            return;
        }

        final PendingResult pendingResult = goAsync();
        try {
            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        String probeHost = savedHost;
                        int probePort = savedPort;
                        if (probeHost.isEmpty()) {
                            ProxyCleaner.HostPort parsed = ProxyCleaner.parseProxyHostPort(currentGlobalProxy);
                            if (parsed != null) {
                                probeHost = parsed.host;
                                probePort = parsed.port;
                            }
                        }
                        boolean reachable = !probeHost.isEmpty()
                                && ProxyCleaner.isProxyReachable(probeHost, probePort, 1500);
                        if (!reachable) {
                            Log.i(TAG, "Stale Cap proxy detected on " + (isBoot ? "boot" : "update") + "; restoring network");
                            String cleanupMode = wasActive
                                    ? GuardPrefs.getMode(context)
                                    : (hasStaleVpn ? "vpn" : "proxy");
                            boolean ok = ProxyCleaner.cleanup(
                                    context,
                                    cleanupMode,
                                    GuardPrefs.getRedirPort(context));
                            String reason = context.getString(isBoot ? R.string.reason_boot : R.string.reason_update);
                            GuardPrefs.recordCleanup(context, reason, ok);
                            if (ok) {
                                ProxyGuardService.postRestoredNotification(context, reason);
                            }
                        }
                    } finally {
                        pendingResult.finish();
                    }
                }
            }, "cap-guard-boot-check").start();
        } catch (Throwable t) {
            Log.w(TAG, "Failed starting boot check thread: " + t.getMessage());
            pendingResult.finish();
        }
    }
}
