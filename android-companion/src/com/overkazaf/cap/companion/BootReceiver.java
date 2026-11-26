package com.overkazaf.cap.companion;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Clears stale Android proxy settings after a device reboot (or when a running
 * Cap Guard session was interrupted by an app upgrade) if the desktop proxy is
 * no longer reachable.
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
        final String currentGlobalProxy = ProxyCleaner.getGlobalHttpProxy(context);

        // On app upgrade, only recover if a Cap Guard session was actually active
        // (avoid racing with desktop SetupDetailed upgrading the APK before starting proxy).
        if (isUpdate && !wasActive) {
            return;
        }
        if (!wasActive && currentGlobalProxy.isEmpty()) {
            return;
        }

        final PendingResult pendingResult = goAsync();
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    String host = GuardPrefs.getProxyHost(context);
                    int port = GuardPrefs.getProxyPort(context);
                    boolean reachable = !host.isEmpty() && ProxyCleaner.isProxyReachable(host, port, 1500);
                    if (!reachable && (wasActive || !currentGlobalProxy.isEmpty())) {
                        Log.i(TAG, "Stale proxy detected on " + (isBoot ? "boot" : "update") + "; restoring network");
                        boolean ok = ProxyCleaner.cleanup(
                                context,
                                GuardPrefs.getMode(context),
                                GuardPrefs.getRedirPort(context));
                        String reason = context.getString(isBoot ? R.string.reason_boot : R.string.reason_update);
                        GuardPrefs.recordCleanup(context, reason, ok);
                        ProxyGuardService.postRestoredNotification(context, reason);
                    }
                } finally {
                    pendingResult.finish();
                }
            }
        }, "cap-guard-boot-check").start();
    }
}
