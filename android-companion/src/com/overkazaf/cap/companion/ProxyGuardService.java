package com.overkazaf.cap.companion;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Foreground service that monitors reachability of the desktop cap MITM proxy
 * and autonomously restores Android network connectivity if the proxy becomes
 * unreachable, USB disconnects, or the user taps "Restore Network".
 */
public class ProxyGuardService extends Service {
    private static final String TAG = "CapGuardService";

    public static final String ACTION_START = "com.overkazaf.cap.companion.ACTION_START";
    public static final String ACTION_STOP = "com.overkazaf.cap.companion.ACTION_STOP";
    public static final String ACTION_RESTORE = "com.overkazaf.cap.companion.ACTION_RESTORE";
    public static final String ACTION_STATUS_CHANGED = "com.overkazaf.cap.companion.STATUS_CHANGED";

    public static final String EXTRA_PROXY_HOST = "proxy_host";
    public static final String EXTRA_PROXY_PORT = "proxy_port";
    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_REDIR_PORT = "redir_port";
    public static final String EXTRA_HEARTBEAT_MS = "heartbeat_ms";
    public static final String EXTRA_MISS_THRESHOLD = "miss_threshold";
    public static final String EXTRA_CERT_HASH = "cert_hash";
    public static final String EXTRA_CERT_FP = "cert_fp";
    public static final String EXTRA_CLEANUP_DONE = "cleanup_done";
    public static final String EXTRA_CLEANUP_OK = "cleanup_ok";

    public static final String CHANNEL_ACTIVE = "cap_guard_active";
    public static final String CHANNEL_EVENTS = "cap_guard_events";
    private static final int NOTIF_ID_ACTIVE = 1001;
    private static final int NOTIF_ID_RESTORED = 1002;

    private static final int PROBE_TIMEOUT_MS = 1500;
    private static final int DEFAULT_HEARTBEAT_MS = 3000;
    private static final int DEFAULT_MISS_THRESHOLD = 3;

    private static volatile boolean sRunning = false;
    private static volatile String sProxyHost = "";
    private static volatile int sProxyPort = 8080;
    private static volatile String sMode = "proxy";
    private static volatile String sRedirPort = "9999";

    private final AtomicBoolean watchdogRunning = new AtomicBoolean(false);
    private final AtomicBoolean cleanedUp = new AtomicBoolean(false);
    private final ExecutorService cleanupExecutor = Executors.newSingleThreadExecutor();
    private Thread watchdogThread;
    private BroadcastReceiver powerReceiver;

    private volatile String proxyHost = "";
    private volatile int proxyPort = 8080;
    private volatile String mode = "proxy";
    private volatile String redirPort = "9999";
    private volatile int heartbeatMs = DEFAULT_HEARTBEAT_MS;
    private volatile int missThreshold = DEFAULT_MISS_THRESHOLD;
    private volatile boolean inForeground = false;

    public static boolean isServiceRunning() {
        return sRunning;
    }

    public static String getRunningHost() {
        return sRunning ? sProxyHost : "";
    }

    public static int getRunningPort() {
        return sProxyPort;
    }

    public static String getRunningMode() {
        return sMode;
    }

    public static String getRunningRedirPort() {
        return sRedirPort;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ensureNotificationChannels(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        boolean isStop = ACTION_STOP.equals(action) || "STOP".equalsIgnoreCase(action);
        boolean isRestore = ACTION_RESTORE.equals(action) || "RESTORE".equalsIgnoreCase(action);

        if (isStop || isRestore) {
            final boolean wasRunning = sRunning;
            // Android 8-14 FGS contract: if invoked via startForegroundService() while not yet
            // foreground, promote briefly before stopping so ForegroundServiceDidNotStartInTimeException
            // can never occur.
            if (!inForeground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try {
                    startForegroundCompat(buildStoppingNotification());
                } catch (Throwable t) {
                    Log.w(TAG, "Brief stop FGS promotion failed: " + t.getMessage());
                }
            }
            String reason = getString(isRestore ? R.string.reason_manual : R.string.reason_stop);
            scheduleCleanupAndStop(reason, isRestore, wasRunning);
            return START_NOT_STICKY;
        }

        // Start or update watchdog session
        if (intent != null && (ACTION_START.equals(action) || "START".equalsIgnoreCase(action) || intent.hasExtra(EXTRA_PROXY_HOST))) {
            proxyHost = readStringExtra(intent, EXTRA_PROXY_HOST, GuardPrefs.getProxyHost(this));
            proxyPort = readIntExtra(intent, EXTRA_PROXY_PORT, GuardPrefs.getProxyPort(this));
            mode = readStringExtra(intent, EXTRA_MODE, GuardPrefs.getMode(this));
            if (mode.isEmpty()) {
                mode = "proxy";
            }
            redirPort = readStringExtra(intent, EXTRA_REDIR_PORT, GuardPrefs.getRedirPort(this));
            if (redirPort.isEmpty()) {
                redirPort = "9999";
            }
            heartbeatMs = clamp(readIntExtra(intent, EXTRA_HEARTBEAT_MS, DEFAULT_HEARTBEAT_MS), 1000, 30000);
            missThreshold = clamp(readIntExtra(intent, EXTRA_MISS_THRESHOLD, DEFAULT_MISS_THRESHOLD), 1, 20);
            String certHash = intent.getStringExtra(EXTRA_CERT_HASH);
            String certFp = intent.getStringExtra(EXTRA_CERT_FP);
            if ((certHash != null && !certHash.trim().isEmpty()) || (certFp != null && !certFp.trim().isEmpty())) {
                GuardPrefs.saveCertMeta(this, certHash, certFp, null);
            }
        } else {
            // Restarted by system — restore saved session
            proxyHost = GuardPrefs.getProxyHost(this);
            proxyPort = GuardPrefs.getProxyPort(this);
            mode = GuardPrefs.getMode(this);
            redirPort = GuardPrefs.getRedirPort(this);
            heartbeatMs = GuardPrefs.getHeartbeatMs(this);
            missThreshold = GuardPrefs.getMissThreshold(this);
        }

        if (proxyHost == null || proxyHost.trim().isEmpty()) {
            Log.w(TAG, "No proxy_host provided; stopping guard");
            if (!inForeground && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                try {
                    startForegroundCompat(buildStoppingNotification());
                } catch (Throwable ignored) {
                }
            }
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }

        cleanedUp.set(false);
        sRunning = true;
        sProxyHost = proxyHost;
        sProxyPort = proxyPort;
        sMode = mode;
        sRedirPort = redirPort;
        GuardPrefs.saveSession(this, proxyHost, proxyPort, mode, redirPort, heartbeatMs, missThreshold);

        // Cancel any previous "restored" notification when starting a fresh session
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.cancel(NOTIF_ID_RESTORED);
        }

        startForegroundCompat(buildActiveNotification(0));
        registerPowerReceiver();
        startWatchdogLoop();
        broadcastStatusChanged(false, false);

        return START_REDELIVER_INTENT;
    }

    @Override
    public void onDestroy() {
        stopWatchdogLoop();
        unregisterPowerReceiver();
        sRunning = false;
        sProxyHost = "";
        inForeground = false;
        cleanupExecutor.shutdown();
        broadcastStatusChanged(false, false);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void startForegroundCompat(Notification notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID_ACTIVE, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID_ACTIVE, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIF_ID_ACTIVE, notification);
        }
        inForeground = true;
    }

    private void stopForegroundCompat() {
        try {
            if (Build.VERSION.SDK_INT >= 24) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
        } catch (Throwable ignored) {
        }
        inForeground = false;
    }

    private void registerPowerReceiver() {
        if (powerReceiver != null) {
            return;
        }
        powerReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (Intent.ACTION_POWER_DISCONNECTED.equals(intent.getAction())) {
                    // USB unplugged: immediately probe proxy on background thread; if unreachable, clean up at once.
                    new Thread(new Runnable() {
                        @Override
                        public void run() {
                            if (!watchdogRunning.get()) {
                                return;
                            }
                            boolean reachable = ProxyCleaner.isProxyReachable(proxyHost, proxyPort, 1200);
                            if (!reachable && watchdogRunning.get()) {
                                Log.i(TAG, "USB disconnected and proxy unreachable — restoring network immediately");
                                scheduleCleanupAndStop(getString(R.string.reason_usb), false, true);
                            }
                        }
                    }, "cap-guard-power-probe").start();
                }
            }
        };
        IntentFilter filter = new IntentFilter(Intent.ACTION_POWER_DISCONNECTED);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(powerReceiver, filter, Context.RECEIVER_EXPORTED);
        } else {
            registerReceiver(powerReceiver, filter);
        }
    }

    private void unregisterPowerReceiver() {
        if (powerReceiver != null) {
            try {
                unregisterReceiver(powerReceiver);
            } catch (Throwable ignored) {
            }
            powerReceiver = null;
        }
    }

    private synchronized void startWatchdogLoop() {
        stopWatchdogLoop();
        watchdogRunning.set(true);
        watchdogThread = new Thread(new Runnable() {
            @Override
            public void run() {
                int misses = 0;
                // Initial settle delay before first heartbeat check
                if (!sleepInterruptibly(heartbeatMs)) {
                    return;
                }
                while (watchdogRunning.get()) {
                    boolean ok = ProxyCleaner.isProxyReachable(proxyHost, proxyPort, PROBE_TIMEOUT_MS);
                    if (!watchdogRunning.get()) {
                        return;
                    }
                    if (ok) {
                        if (misses != 0) {
                            misses = 0;
                            GuardPrefs.updateMissCount(ProxyGuardService.this, 0);
                            updateActiveNotification(0);
                            broadcastStatusChanged(false, false);
                        }
                    } else {
                        misses++;
                        GuardPrefs.updateMissCount(ProxyGuardService.this, misses);
                        updateActiveNotification(misses);
                        broadcastStatusChanged(false, false);
                        Log.w(TAG, "Proxy heartbeat miss " + misses + "/" + missThreshold + " for " + proxyHost + ":" + proxyPort);
                        if (misses >= missThreshold) {
                            scheduleCleanupAndStop(getString(R.string.reason_heartbeat), false, true);
                            return;
                        }
                    }
                    if (!sleepInterruptibly(heartbeatMs)) {
                        return;
                    }
                }
            }
        }, "cap-guard-watchdog");
        watchdogThread.setDaemon(true);
        watchdogThread.start();
    }

    private synchronized void stopWatchdogLoop() {
        watchdogRunning.set(false);
        if (watchdogThread != null) {
            watchdogThread.interrupt();
            watchdogThread = null;
        }
    }

    private boolean sleepInterruptibly(long ms) {
        try {
            Thread.sleep(ms);
            return watchdogRunning.get();
        } catch (InterruptedException e) {
            return false;
        }
    }

    private void scheduleCleanupAndStop(final String reason, final boolean isManualRestore, final boolean wasRunning) {
        if (!cleanedUp.compareAndSet(false, true)) {
            return;
        }
        stopWatchdogLoop();
        unregisterPowerReceiver();
        sRunning = false;
        sProxyHost = "";

        cleanupExecutor.execute(new Runnable() {
            @Override
            public void run() {
                boolean hasProxy = !ProxyCleaner.getGlobalHttpProxy(ProxyGuardService.this).isEmpty();
                boolean hasVpn = ProxyCleaner.hasStaleVpnMarker();
                boolean prefsActive = GuardPrefs.isActive(ProxyGuardService.this);

                // If ACTION_STOP arrives when the guard was already idle and no proxy/VPN is active,
                // stop silently without forging a redundant cleanup timestamp or notification.
                if (!isManualRestore && !wasRunning && !hasProxy && !hasVpn && !prefsActive) {
                    stopForegroundCompat();
                    broadcastStatusChanged(false, false);
                    stopSelf();
                    return;
                }

                String activeMode = mode;
                String activeRedir = redirPort;
                if (activeMode == null || activeMode.isEmpty()) {
                    activeMode = GuardPrefs.getMode(ProxyGuardService.this);
                }
                if (activeRedir == null || activeRedir.isEmpty()) {
                    activeRedir = GuardPrefs.getRedirPort(ProxyGuardService.this);
                }
                if (!wasRunning && !hasVpn) {
                    activeMode = "proxy";
                }

                boolean ok = ProxyCleaner.cleanup(ProxyGuardService.this, activeMode, activeRedir);
                GuardPrefs.recordCleanup(ProxyGuardService.this, reason, ok);

                stopForegroundCompat();
                if (wasRunning || hasProxy || hasVpn) {
                    postRestoredNotification(ProxyGuardService.this, reason);
                }
                broadcastStatusChanged(true, ok);
                stopSelf();
            }
        });
    }

    private void broadcastStatusChanged(boolean cleanupDone, boolean cleanupOk) {
        Intent i = new Intent(ACTION_STATUS_CHANGED);
        i.setPackage(getPackageName());
        if (cleanupDone) {
            i.putExtra(EXTRA_CLEANUP_DONE, true);
            i.putExtra(EXTRA_CLEANUP_OK, cleanupOk);
        }
        sendBroadcast(i);
    }

    private void updateActiveNotification(int misses) {
        if (!inForeground || !sRunning) {
            return;
        }
        try {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.notify(NOTIF_ID_ACTIVE, buildActiveNotification(misses));
            }
        } catch (Throwable ignored) {
        }
    }

    private Notification buildStoppingNotification() {
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ACTIVE)
                : new Notification.Builder(this);
        return builder.setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(getString(R.string.notif_stopping_title))
                .setContentText(getString(R.string.notif_stopping_text))
                .setOngoing(false)
                .setOnlyAlertOnce(true)
                .build();
    }

    private Notification buildActiveNotification(int misses) {
        String addr = proxyHost + ":" + proxyPort;
        String modeLabel = "vpn".equalsIgnoreCase(mode)
                ? getString(R.string.mode_vpn_short)
                : getString(R.string.mode_proxy);

        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPi = PendingIntent.getActivity(
                this, 0, openIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent restoreIntent = new Intent(this, ProxyGuardService.class);
        restoreIntent.setAction(ACTION_RESTORE);
        PendingIntent restorePi = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? PendingIntent.getForegroundService(
                        this, 1, restoreIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
                : PendingIntent.getService(
                        this, 1, restoreIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        String contentText = misses > 0
                ? getString(R.string.notif_active_text_miss, addr, misses, missThreshold)
                : getString(R.string.notif_active_text, addr);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ACTIVE)
                : new Notification.Builder(this);

        builder.setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(getString(R.string.notif_active_title, modeLabel))
                .setContentText(contentText)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(openPi)
                .addAction(new Notification.Action.Builder(
                        R.drawable.ic_shield,
                        getString(R.string.notif_action_restore),
                        restorePi).build());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        }

        return builder.build();
    }

    public static void postRestoredNotification(Context ctx, String reason) {
        ensureNotificationChannels(ctx);
        NotificationManager nm = (NotificationManager) ctx.getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }
        Intent openIntent = new Intent(ctx, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPi = PendingIntent.getActivity(
                ctx, 2, openIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(ctx, CHANNEL_EVENTS)
                : new Notification.Builder(ctx);

        builder.setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(ctx.getString(R.string.notif_restored_title))
                .setContentText(ctx.getString(R.string.notif_restored_text, reason))
                .setAutoCancel(true)
                .setOngoing(false)
                .setContentIntent(openPi);

        nm.notify(NOTIF_ID_RESTORED, builder.build());
    }

    public static void ensureNotificationChannels(Context ctx) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationManager nm = (NotificationManager) ctx.getSystemService(NOTIFICATION_SERVICE);
        if (nm == null) {
            return;
        }
        NotificationChannel active = new NotificationChannel(
                CHANNEL_ACTIVE,
                ctx.getString(R.string.channel_active_name),
                NotificationManager.IMPORTANCE_LOW);
        active.setDescription(ctx.getString(R.string.channel_active_desc));
        active.setShowBadge(false);
        nm.createNotificationChannel(active);

        NotificationChannel events = new NotificationChannel(
                CHANNEL_EVENTS,
                ctx.getString(R.string.channel_events_name),
                NotificationManager.IMPORTANCE_DEFAULT);
        events.setDescription(ctx.getString(R.string.channel_events_desc));
        nm.createNotificationChannel(events);
    }

    private static String readStringExtra(Intent intent, String key, String fallback) {
        String v = intent.getStringExtra(key);
        return v != null ? v.trim() : (fallback != null ? fallback : "");
    }

    private static int readIntExtra(Intent intent, String key, int fallback) {
        String s = intent.getStringExtra(key);
        if (s != null && !s.trim().isEmpty()) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return intent.getIntExtra(key, fallback);
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
