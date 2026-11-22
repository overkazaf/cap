package com.overkazaf.cap.companion;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * Clears stale Android proxy settings after a crash or device reboot when a
 * previous Cap capture session was left active and the desktop proxy is no
 * longer reachable.
 */
public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "CapGuardBoot";

    @Override
    public void onReceive(final Context context, Intent intent) {
        String action = intent != null ? intent.getAction() : null;
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            return;
        }

        final boolean wasActive = GuardPrefs.isActive(context);
        final String currentGlobalProxy = ProxyCleaner.getGlobalHttpProxy(context);
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
                        Log.i(TAG, "Stale proxy detected on boot/update; restoring network");
                        boolean ok = ProxyCleaner.cleanup(
                                context,
                                GuardPrefs.getMode(context),
                                GuardPrefs.getRedirPort(context));
                        String reason = context.getString(R.string.reason_boot);
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
