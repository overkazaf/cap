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

    public static final String CHANNEL_ACTIVE = "cap_guard_active";
    public static final String CHANNEL_EVENTS = "cap_guard_events";
    private static final int NOTIF_ID_ACTIVE = 1001;
    private static final int NOTIF_ID_RESTORED = 1002;

    private static final int PROBE_TIMEOUT_MS = 1500;
    private static final int DEFAULT_HEARTBEAT_MS = 3000;
    private static final int DEFAULT_MISS_THRESHOLD = 3;

    private static volatile boolean sRunning = false;

    private final AtomicBoolean watchdogRunning = new AtomicBoolean(false);
    private final AtomicBoolean cleanedUp = new AtomicBoolean(false);
    private Thread watchdogThread;
    private BroadcastReceiver powerReceiver;

    private volatile String proxyHost = "";
    private volatile int proxyPort = 8080;
    private volatile String mode = "proxy";
    private volatile String redirPort = "9999";
    private volatile int heartbeatMs = DEFAULT_HEARTBEAT_MS;
    private volatile int missThreshold = DEFAULT_MISS_THRESHOLD;

    public static boolean isServiceRunning() {
        return sRunning;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        ensureNotificationChannels(this);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action) || "STOP".equalsIgnoreCase(action)) {
            performCleanupAndStop(getString(R.string.reason_stop));
            return START_NOT_STICKY;
        }
        if (ACTION_RESTORE.equals(action) || "RESTORE".equalsIgnoreCase(action)) {
            performCleanupAndStop(getString(R.string.reason_manual));
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
            stopSelf();
            return START_NOT_STICKY;
        }

        cleanedUp.set(false);
        sRunning = true;
        GuardPrefs.saveSession(this, proxyHost, proxyPort, mode, redirPort, heartbeatMs, missThreshold);

        // Cancel any previous "restored" notification when starting a fresh session
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null) {
            nm.cancel(NOTIF_ID_RESTORED);
        }

        startForegroundCompat(buildActiveNotification());
        registerPowerReceiver();
        startWatchdogLoop();
        broadcastStatusChanged();

        return START_REDELIVER_INTENT;
    }

    @Override
    public void onDestroy() {
        stopWatchdogLoop();
        unregisterPowerReceiver();
        sRunning = false;
        broadcastStatusChanged();
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
                                performCleanupAndStop(getString(R.string.reason_usb));
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
                            broadcastStatusChanged();
                        }
                    } else {
                        misses++;
                        GuardPrefs.updateMissCount(ProxyGuardService.this, misses);
                        broadcastStatusChanged();
                        Log.w(TAG, "Proxy heartbeat miss " + misses + "/" + missThreshold + " for " + proxyHost + ":" + proxyPort);
                        if (misses >= missThreshold) {
                            performCleanupAndStop(getString(R.string.reason_heartbeat));
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

    private void performCleanupAndStop(String reason) {
        if (!cleanedUp.compareAndSet(false, true)) {
            return;
        }
        stopWatchdogLoop();
        unregisterPowerReceiver();

        String activeMode = mode;
        String activeRedir = redirPort;
        if (activeMode == null || activeMode.isEmpty()) {
            activeMode = GuardPrefs.getMode(this);
        }
        if (activeRedir == null || activeRedir.isEmpty()) {
            activeRedir = GuardPrefs.getRedirPort(this);
        }

        boolean ok = ProxyCleaner.cleanup(this, activeMode, activeRedir);
        GuardPrefs.recordCleanup(this, reason, ok);
        sRunning = false;
        broadcastStatusChanged();

        try {
            if (Build.VERSION.SDK_INT >= 24) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
        } catch (Throwable ignored) {
        }

        postRestoredNotification(this, reason);
        stopSelf();
    }

    private void broadcastStatusChanged() {
        Intent i = new Intent(ACTION_STATUS_CHANGED);
        i.setPackage(getPackageName());
        sendBroadcast(i);
    }

    private Notification buildActiveNotification() {
        String addr = proxyHost + ":" + proxyPort;
        String modeLabel = "vpn".equalsIgnoreCase(mode)
                ? getString(R.string.mode_vpn)
                : getString(R.string.mode_proxy);

        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPi = PendingIntent.getActivity(
                this, 0, openIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent restoreIntent = new Intent(this, ProxyGuardService.class);
        restoreIntent.setAction(ACTION_RESTORE);
        PendingIntent restorePi = PendingIntent.getService(
                this, 1, restoreIntent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ACTIVE)
                : new Notification.Builder(this);

        builder.setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(getString(R.string.notif_active_title, modeLabel))
                .setContentText(getString(R.string.notif_active_text, addr))
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
