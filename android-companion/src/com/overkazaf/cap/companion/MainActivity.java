package com.overkazaf.cap.companion;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.security.KeyChain;
import android.util.Base64;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Dark/light-aware status and control screen for Cap Guard.
 *
 * All blocking inspections (AndroidCAStore, Settings.Global, filesystem, root)
 * run on a single-thread background executor with generation tracking so UI
 * remains responsive and never applies stale snapshots.
 */
public class MainActivity extends Activity {
    public static final String EXTRA_INSTALL_CERT = "install_cert";
    public static final String EXTRA_CERT_PATH = "cert_path";
    public static final String EXTRA_CERT_B64 = "cert_b64";
    public static final String EXTRA_CERT_HASH = "cert_hash";
    public static final String EXTRA_CERT_FP = "cert_fp";

    private static final int REQ_INSTALL_CERT = 2001;
    private static final int REQ_POST_NOTIFICATIONS = 2002;
    private static final int MAX_CERT_B64_CHARS = 65536;
    private static final int MAX_CERT_BYTES = 48 * 1024;
    private static final int MAX_READ_BYTES = 64 * 1024;

    private final ExecutorService ioExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicInteger refreshGen = new AtomicInteger(0);

    // Theme palette
    private boolean isDarkTheme;
    private int bgColor;
    private int cardColor;
    private int borderColor;
    private int dividerColor;
    private int textPrimary;
    private int textMuted;
    private int disabledBg;
    private int disabledText;

    // Header
    private TextView statusBadgeView;

    // Card 1: Proxy & Watchdog
    private TextView systemProxyValue;
    private TextView watchdogValue;
    private LinearLayout modeRowContainer;
    private View modeRowDivider;
    private TextView modeValue;
    private TextView lastCleanupValue;
    private Button startWatchdogBtn;
    private Button proxyActionBtn;

    // Card 2: CA Certificate
    private TextView certStatusValue;
    private TextView certDetailValue;
    private Button certActionBtn;

    // Card 3: Permissions & Environment
    private LinearLayout permRow;
    private TextView permissionValue;
    private LinearLayout batteryRow;
    private TextView batteryValue;
    private LinearLayout notifRow;
    private TextView notifValue;
    private TextView rootValue;

    // Bottom refresh
    private Button refreshBtn;

    // Live state
    private String pendingCertPath;
    private UiSnapshot latestSnapshot;
    private boolean localCleanupBusy = false;
    private boolean serviceCleanupBusy = false;
    private boolean refreshBusy = false;
    private boolean pendingManualToast = false;

    private static final class UiSnapshot {
        boolean serviceRunning;
        boolean prefsActive;
        boolean staleVpn;
        String globalProxy = "";
        String guardHost = "";
        int guardPort = 8080;
        String guardMode = "proxy";
        String redirPort = "9999";
        int missCount;
        int missThreshold = 3;
        long lastCleanupTs;
        String lastCleanupReason = "";
        boolean lastCleanupOk;
        boolean hasSecureSettings;
        boolean batteryWhitelisted;
        boolean notificationsEnabled;
        boolean suAvailable;
        CertInspector.CertCheckResult certStatus;
    }

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent != null && intent.getBooleanExtra(ProxyGuardService.EXTRA_CLEANUP_DONE, false)) {
                serviceCleanupBusy = false;
                boolean ok = intent.getBooleanExtra(ProxyGuardService.EXTRA_CLEANUP_OK, false);
                Toast.makeText(
                        MainActivity.this,
                        ok ? R.string.toast_cleaned : R.string.toast_clean_failed,
                        Toast.LENGTH_SHORT).show();
            }
            requestRefresh(false, false);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int nightMode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        isDarkTheme = (nightMode == Configuration.UI_MODE_NIGHT_YES);
        initPalette();
        setContentView(buildContentView());
        applySystemBarColors();
        handleIntentExtras(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntentExtras(intent);
        requestRefresh(false, false);
    }

    @Override
    protected void onResume() {
        super.onResume();
        IntentFilter filter = new IntentFilter(ProxyGuardService.ACTION_STATUS_CHANGED);
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            registerReceiver(statusReceiver, filter);
        }
        if (serviceCleanupBusy && !ProxyGuardService.isServiceRunning() && !ProxyGuardService.isCleanupInProgress()) {
            serviceCleanupBusy = false;
        }
        requestRefresh(false, false);
    }

    @Override
    protected void onPause() {
        try {
            unregisterReceiver(statusReceiver);
        } catch (Throwable ignored) {
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        mainHandler.removeCallbacksAndMessages(null);
        ioExecutor.shutdownNow();
        super.onDestroy();
    }

    private void initPalette() {
        bgColor = isDarkTheme ? Color.parseColor("#0B0F17") : Color.parseColor("#F4F6FA");
        cardColor = isDarkTheme ? Color.parseColor("#131A27") : Color.parseColor("#FFFFFF");
        borderColor = isDarkTheme ? Color.parseColor("#243045") : Color.parseColor("#E2E8F0");
        dividerColor = isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#EEF2F6");
        textPrimary = isDarkTheme ? Color.parseColor("#F1F5F9") : Color.parseColor("#0F172A");
        textMuted = isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#64748B");
        disabledBg = isDarkTheme ? Color.parseColor("#1A2233") : Color.parseColor("#E2E8F0");
        disabledText = isDarkTheme ? Color.parseColor("#64748B") : Color.parseColor("#94A3B8");
    }

    private void applySystemBarColors() {
        Window window = getWindow();
        if (window == null) {
            return;
        }
        try {
            window.setStatusBarColor(bgColor);
            window.setNavigationBarColor(bgColor);
            // Ensure PhoneWindow's DecorView is installed before calling getInsetsController()
            // on API 30+ (calling getInsetsController() with null mDecor throws NPE on Android 11-15).
            View decor = window.getDecorView();
            if (decor == null) {
                return;
            }
            if (Build.VERSION.SDK_INT >= 30) {
                WindowInsetsController controller = window.getInsetsController();
                if (controller != null) {
                    int mask = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                            | WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS;
                    controller.setSystemBarsAppearance(isDarkTheme ? 0 : mask, mask);
                }
            } else if (!isDarkTheme && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                int flags = decor.getSystemUiVisibility() | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
                }
                decor.setSystemUiVisibility(flags);
            }
        } catch (Throwable ignored) {
        }
    }

    private View buildContentView() {
        final ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(bgColor);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);

        final LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        final int padH = dp(18);
        final int padTop = dp(20);
        final int padBottom = dp(26);
        root.setPadding(padH, padTop, padH, padBottom);
        scroll.addView(root);

        // Edge-to-edge safe insets for Android 14/15 and gesture nav devices
        scroll.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
            @Override
            public WindowInsets onApplyWindowInsets(View v, WindowInsets insets) {
                if (insets == null) {
                    return null;
                }
                int top = 0;
                int bottom = 0;
                int left = 0;
                int right = 0;
                if (Build.VERSION.SDK_INT >= 30) {
                    android.graphics.Insets sys = insets.getInsets(
                            WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
                    top = sys.top;
                    bottom = sys.bottom;
                    left = sys.left;
                    right = sys.right;
                }
                root.setPadding(padH + left, padTop + top, padH + right, padBottom + bottom);
                return insets;
            }
        });

        // Header
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(header);

        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.ic_launcher);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(42), dp(42));
        iconLp.rightMargin = dp(12);
        header.addView(icon, iconLp);

        LinearLayout titleCol = new LinearLayout(this);
        titleCol.setOrientation(LinearLayout.VERTICAL);
        header.addView(titleCol, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextColor(textPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 19);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        titleCol.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(getString(R.string.app_subtitle, resolveVersionName()));
        subtitle.setTextColor(textMuted);
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        titleCol.addView(subtitle);

        statusBadgeView = new TextView(this);
        statusBadgeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        statusBadgeView.setTypeface(Typeface.DEFAULT_BOLD);
        statusBadgeView.setPadding(dp(10), dp(5), dp(10), dp(5));
        LinearLayout.LayoutParams badgeLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        badgeLp.leftMargin = dp(8);
        header.addView(statusBadgeView, badgeLp);

        // ===== Card 1: Proxy & Watchdog =====
        LinearLayout proxyCard = addCard(root, R.string.section_proxy, dp(18));
        systemProxyValue = addRow(proxyCard, R.string.label_global_proxy, true, false);
        addDivider(proxyCard);
        watchdogValue = addRow(proxyCard, R.string.label_watchdog, false, false);

        modeRowDivider = addDivider(proxyCard);
        modeRowContainer = new LinearLayout(this);
        modeRowContainer.setOrientation(LinearLayout.VERTICAL);
        proxyCard.addView(modeRowContainer);
        modeValue = addRow(modeRowContainer, R.string.label_mode, false, false);

        addDivider(proxyCard);
        lastCleanupValue = addRow(proxyCard, R.string.label_last_cleanup, false, false);

        LinearLayout proxyBtnRow = new LinearLayout(this);
        proxyBtnRow.setOrientation(LinearLayout.HORIZONTAL);
        LinearLayout.LayoutParams proxyBtnRowLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        proxyBtnRowLp.topMargin = dp(12);
        proxyCard.addView(proxyBtnRow, proxyBtnRowLp);

        startWatchdogBtn = createActionButton(
                getString(R.string.btn_start_watchdog),
                Color.parseColor("#10B981"),
                Color.WHITE,
                Color.TRANSPARENT);
        startWatchdogBtn.setVisibility(View.GONE);
        startWatchdogBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onStartWatchdogClicked();
            }
        });
        LinearLayout.LayoutParams startLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        startLp.rightMargin = dp(8);
        proxyBtnRow.addView(startWatchdogBtn, startLp);

        proxyActionBtn = createActionButton(
                getString(R.string.btn_proxy_idle),
                disabledBg,
                disabledText,
                Color.TRANSPARENT);
        proxyActionBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onProxyActionClicked();
            }
        });
        proxyBtnRow.addView(proxyActionBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        // ===== Card 2: CA Certificate =====
        LinearLayout certCard = addCard(root, R.string.section_cert, dp(14));
        certStatusValue = addRow(certCard, R.string.label_cert_status, false, false);
        certDetailValue = new TextView(this);
        certDetailValue.setTextColor(textMuted);
        certDetailValue.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        certDetailValue.setLineSpacing(dp(2), 1f);
        LinearLayout.LayoutParams certDetailLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        certDetailLp.topMargin = dp(2);
        certCard.addView(certDetailValue, certDetailLp);

        certActionBtn = createActionButton(
                getString(R.string.btn_cert_details),
                cardColor,
                textPrimary,
                borderColor);
        certActionBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onCertActionClicked();
            }
        });
        LinearLayout.LayoutParams certBtnLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        certBtnLp.topMargin = dp(12);
        certCard.addView(certActionBtn, certBtnLp);

        // ===== Card 3: Permissions & Environment =====
        LinearLayout envCard = addCard(root, R.string.section_env, dp(14));
        permRow = addClickableRowContainer(envCard);
        permissionValue = addRow(permRow, R.string.label_permission, false, false);
        permRow.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onPermissionRowClicked();
            }
        });

        addDivider(envCard);
        batteryRow = addClickableRowContainer(envCard);
        batteryValue = addRow(batteryRow, R.string.label_battery, false, false);
        batteryRow.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onBatteryRowClicked();
            }
        });

        addDivider(envCard);
        notifRow = addClickableRowContainer(envCard);
        notifValue = addRow(notifRow, R.string.label_notifications, false, false);
        notifRow.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onNotifRowClicked();
            }
        });

        addDivider(envCard);
        rootValue = addRow(envCard, R.string.label_root, false, false);

        // ===== Refresh Button =====
        refreshBtn = createActionButton(
                getString(R.string.btn_refresh),
                cardColor,
                textPrimary,
                borderColor);
        refreshBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                requestRefresh(true, false);
            }
        });
        LinearLayout.LayoutParams refreshLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        refreshLp.topMargin = dp(16);
        root.addView(refreshBtn, refreshLp);

        // Footer hint
        TextView footer = new TextView(this);
        footer.setText(R.string.footer_hint);
        footer.setTextColor(textMuted);
        footer.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        footer.setLineSpacing(dp(3), 1f);
        LinearLayout.LayoutParams footerLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        footerLp.topMargin = dp(14);
        root.addView(footer, footerLp);

        return scroll;
    }

    private LinearLayout addCard(LinearLayout parent, int sectionTitleRes, int topMarginPx) {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(roundedRect(cardColor, borderColor, dp(12), dp(1)));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.topMargin = topMarginPx;
        parent.addView(card, lp);

        TextView header = new TextView(this);
        header.setText(sectionTitleRes);
        header.setTextColor(textMuted);
        header.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        header.setTypeface(Typeface.DEFAULT_BOLD);
        header.setAllCaps(false);
        LinearLayout.LayoutParams hLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        hLp.bottomMargin = dp(6);
        card.addView(header, hLp);
        return card;
    }

    private LinearLayout addClickableRowContainer(LinearLayout parent) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setClickable(true);
        box.setFocusable(true);
        parent.addView(box, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        return box;
    }

    private View addDivider(LinearLayout parent) {
        View line = new View(this);
        line.setBackgroundColor(dividerColor);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
        lp.topMargin = dp(4);
        lp.bottomMargin = dp(4);
        parent.addView(line, lp);
        return line;
    }

    private TextView addRow(LinearLayout parent, int labelRes, boolean mono, boolean tightBottom) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(4), 0, tightBottom ? 0 : dp(4));

        TextView label = new TextView(this);
        label.setText(labelRes);
        label.setTextColor(textMuted);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        row.addView(label);

        TextView value = new TextView(this);
        value.setTextColor(textPrimary);
        value.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        if (mono) {
            value.setTypeface(Typeface.MONOSPACE);
        }
        LinearLayout.LayoutParams valLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        valLp.topMargin = dp(2);
        row.addView(value, valLp);

        parent.addView(row);
        return value;
    }

    private Button createActionButton(String text, int bg, int fg, int stroke) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setAllCaps(false);
        btn.setTextColor(fg);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        btn.setTypeface(Typeface.DEFAULT_BOLD);
        btn.setMinHeight(dp(44));
        btn.setMinimumHeight(dp(44));
        btn.setPadding(dp(14), dp(10), dp(14), dp(10));
        btn.setBackground(roundedRect(bg, stroke, dp(10), stroke == Color.TRANSPARENT ? 0 : dp(1)));
        return btn;
    }

    private void styleButton(Button btn, String text, int bg, int fg, int stroke, boolean enabled) {
        btn.setText(text);
        btn.setTextColor(fg);
        btn.setBackground(roundedRect(bg, stroke, dp(10), stroke == Color.TRANSPARENT ? 0 : dp(1)));
        btn.setEnabled(enabled);
        btn.setAlpha(enabled ? 1f : 0.72f);
    }

    private String resolveVersionName() {
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), 0);
            if (pi != null && pi.versionName != null && !pi.versionName.isEmpty()) {
                return pi.versionName;
            }
        } catch (Throwable ignored) {
        }
        return "1.2.1";
    }

    private void runIo(Runnable task) {
        if (isFinishing() || isDestroyed() || ioExecutor.isShutdown()) {
            return;
        }
        try {
            ioExecutor.execute(task);
        } catch (RejectedExecutionException ignored) {
        }
    }

    // ==================== Async Inspection & Rendering ====================

    private void requestRefresh(final boolean manualFeedback, final boolean verifyCertToast) {
        final int gen = refreshGen.incrementAndGet();
        final String certPathSnapshot = pendingCertPath;
        if (manualFeedback) {
            refreshBusy = true;
            pendingManualToast = true;
            styleButton(refreshBtn, getString(R.string.btn_refreshing), cardColor, textMuted, borderColor, false);
        }

        runIo(new Runnable() {
            @Override
            public void run() {
                final UiSnapshot snap = collectSnapshot(certPathSnapshot);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed() || refreshGen.get() != gen) {
                            return;
                        }
                        latestSnapshot = snap;
                        if (refreshBusy) {
                            refreshBusy = false;
                            styleButton(refreshBtn, getString(R.string.btn_refresh), cardColor, textPrimary, borderColor, true);
                        }
                        renderSnapshot(snap);
                        if (pendingManualToast) {
                            pendingManualToast = false;
                            Toast.makeText(MainActivity.this, R.string.toast_refreshed, Toast.LENGTH_SHORT).show();
                        }
                        if (verifyCertToast && snap.certStatus != null && snap.certStatus.installed) {
                            Toast.makeText(MainActivity.this, R.string.toast_cert_verified, Toast.LENGTH_SHORT).show();
                        }
                    }
                });
            }
        });
    }

    private UiSnapshot collectSnapshot(String preferredCertPath) {
        Context appCtx = getApplicationContext();
        UiSnapshot snap = new UiSnapshot();
        snap.serviceRunning = ProxyGuardService.isServiceRunning();
        snap.prefsActive = GuardPrefs.isActive(appCtx);
        snap.globalProxy = ProxyCleaner.getGlobalHttpProxy(appCtx);
        snap.staleVpn = ProxyCleaner.hasStaleVpnMarker();

        // Reconcile ghost active flag if service died and nothing is actually active on device
        if (!snap.serviceRunning && snap.prefsActive && snap.globalProxy.isEmpty() && !snap.staleVpn) {
            GuardPrefs.clearActiveFlag(appCtx);
            snap.prefsActive = false;
        }

        if (snap.serviceRunning) {
            snap.guardHost = ProxyGuardService.getRunningHost();
            snap.guardPort = ProxyGuardService.getRunningPort();
            snap.guardMode = ProxyGuardService.getRunningMode();
            snap.redirPort = ProxyGuardService.getRunningRedirPort();
        } else {
            snap.guardHost = GuardPrefs.getProxyHost(appCtx);
            snap.guardPort = GuardPrefs.getProxyPort(appCtx);
            snap.guardMode = GuardPrefs.getMode(appCtx);
            snap.redirPort = GuardPrefs.getRedirPort(appCtx);
        }

        snap.missCount = GuardPrefs.getMissCount(appCtx);
        snap.missThreshold = GuardPrefs.getMissThreshold(appCtx);
        snap.lastCleanupTs = GuardPrefs.getLastCleanupTs(appCtx);
        snap.lastCleanupReason = GuardPrefs.getLastCleanupReason(appCtx);
        snap.lastCleanupOk = GuardPrefs.getLastCleanupOk(appCtx);

        snap.hasSecureSettings = ProxyCleaner.hasWriteSecureSettings(appCtx);
        snap.batteryWhitelisted = ProxyCleaner.isBatteryOptimizationIgnored(appCtx);
        snap.notificationsEnabled = ProxyCleaner.areNotificationsEnabled(appCtx);
        snap.suAvailable = ProxyCleaner.isSuAvailable();
        snap.certStatus = CertInspector.inspect(appCtx, null, null, preferredCertPath);
        return snap;
    }

    private void renderSnapshot(UiSnapshot snap) {
        boolean hasProxy = !snap.globalProxy.isEmpty();
        boolean isVpnActive = (snap.serviceRunning && "vpn".equalsIgnoreCase(snap.guardMode)) || snap.staleVpn;
        boolean hasActiveTrafficRouting = hasProxy || isVpnActive;

        // 1. Header Status Pill
        if (snap.serviceRunning) {
            statusBadgeView.setText(R.string.status_protected);
            statusBadgeView.setTextColor(Color.parseColor("#10B981"));
            statusBadgeView.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#0D2F24") : Color.parseColor("#D1FAE5"),
                    Color.parseColor("#10B981"), dp(99), dp(1)));
        } else if (hasActiveTrafficRouting) {
            statusBadgeView.setText(R.string.status_stale);
            statusBadgeView.setTextColor(Color.parseColor("#F59E0B"));
            statusBadgeView.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#31230D") : Color.parseColor("#FEF3C7"),
                    Color.parseColor("#F59E0B"), dp(99), dp(1)));
        } else {
            statusBadgeView.setText(R.string.status_idle);
            statusBadgeView.setTextColor(isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
            statusBadgeView.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#E2E8F0"),
                    Color.TRANSPARENT, dp(99), 0));
        }

        // 2. Card 1 — System Proxy / Watchdog / Mode / Cleanup
        String guardAddr = !snap.guardHost.isEmpty() ? (snap.guardHost + ":" + snap.guardPort) : "";
        if (hasProxy) {
            if (snap.serviceRunning && !guardAddr.isEmpty() && !guardAddr.equals(snap.globalProxy)) {
                systemProxyValue.setText(getString(R.string.value_proxy_mismatch_note, snap.globalProxy, guardAddr));
                systemProxyValue.setTextColor(Color.parseColor("#F59E0B"));
            } else {
                systemProxyValue.setText(snap.globalProxy);
                systemProxyValue.setTextColor(snap.serviceRunning
                        ? Color.parseColor("#10B981")
                        : Color.parseColor("#F59E0B"));
            }
        } else if (isVpnActive) {
            systemProxyValue.setText(getString(R.string.value_proxy_vpn_transparent, snap.redirPort));
            systemProxyValue.setTextColor(snap.serviceRunning
                    ? Color.parseColor("#10B981")
                    : Color.parseColor("#F59E0B"));
        } else {
            systemProxyValue.setText(R.string.value_direct);
            systemProxyValue.setTextColor(textMuted);
        }

        if (snap.serviceRunning) {
            if (snap.missCount > 0) {
                watchdogValue.setText(getString(
                        R.string.value_watchdog_running_miss, guardAddr, snap.missCount, snap.missThreshold));
                watchdogValue.setTextColor(Color.parseColor("#F59E0B"));
            } else {
                watchdogValue.setText(getString(R.string.value_watchdog_running_ok, guardAddr));
                watchdogValue.setTextColor(Color.parseColor("#10B981"));
            }
        } else if (snap.prefsActive && hasActiveTrafficRouting) {
            watchdogValue.setText(R.string.value_watchdog_interrupted);
            watchdogValue.setTextColor(Color.parseColor("#F59E0B"));
        } else {
            watchdogValue.setText(R.string.value_watchdog_stopped);
            watchdogValue.setTextColor(textMuted);
        }

        boolean showMode = snap.serviceRunning || hasActiveTrafficRouting;
        modeRowContainer.setVisibility(showMode ? View.VISIBLE : View.GONE);
        modeRowDivider.setVisibility(showMode ? View.VISIBLE : View.GONE);
        if (showMode) {
            if (isVpnActive) {
                modeValue.setText(getString(R.string.mode_vpn, snap.redirPort));
            } else {
                modeValue.setText(R.string.mode_proxy);
            }
            modeValue.setTextColor(textPrimary);
        }

        if (snap.lastCleanupTs > 0) {
            String timeStr = formatCleanupTime(snap.lastCleanupTs);
            String reason = snap.lastCleanupReason.isEmpty()
                    ? getString(R.string.reason_manual)
                    : snap.lastCleanupReason;
            lastCleanupValue.setText(getString(
                    snap.lastCleanupOk ? R.string.value_cleanup_ok : R.string.value_cleanup_fail,
                    timeStr, reason));
            lastCleanupValue.setTextColor(snap.lastCleanupOk ? textMuted : Color.parseColor("#F59E0B"));
        } else {
            lastCleanupValue.setText(R.string.value_cleanup_none);
            lastCleanupValue.setTextColor(textMuted);
        }

        // State-aware Proxy & Watchdog Buttons
        if (serviceCleanupBusy && !snap.serviceRunning && !ProxyGuardService.isCleanupInProgress()) {
            serviceCleanupBusy = false;
        }
        boolean busy = localCleanupBusy || serviceCleanupBusy || ProxyGuardService.isCleanupInProgress();
        if (busy) {
            startWatchdogBtn.setVisibility(View.GONE);
            styleButton(proxyActionBtn, getString(R.string.btn_working), disabledBg, disabledText, Color.TRANSPARENT, false);
        } else if (snap.serviceRunning) {
            startWatchdogBtn.setVisibility(View.GONE);
            styleButton(proxyActionBtn, getString(R.string.btn_stop_and_clean),
                    Color.parseColor("#EF4444"), Color.WHITE, Color.TRANSPARENT, true);
        } else if (hasActiveTrafficRouting) {
            boolean canStartWatchdog = hasProxy && ProxyCleaner.parseProxyHostPort(snap.globalProxy) != null;
            startWatchdogBtn.setVisibility(canStartWatchdog ? View.VISIBLE : View.GONE);
            if (canStartWatchdog) {
                styleButton(startWatchdogBtn, getString(R.string.btn_start_watchdog),
                        Color.parseColor("#10B981"), Color.WHITE, Color.TRANSPARENT, true);
            }
            styleButton(proxyActionBtn, getString(R.string.btn_clear_proxy),
                    Color.parseColor("#EF4444"), Color.WHITE, Color.TRANSPARENT, true);
        } else {
            startWatchdogBtn.setVisibility(View.GONE);
            styleButton(proxyActionBtn, getString(R.string.btn_proxy_idle),
                    disabledBg, disabledText, borderColor, false);
        }

        // 3. Card 2 — CA Certificate
        renderCertCard(snap.certStatus);

        // 4. Card 3 — Permissions & Environment
        permissionValue.setText(snap.hasSecureSettings ? R.string.value_granted : R.string.value_missing_perm);
        permissionValue.setTextColor(snap.hasSecureSettings ? Color.parseColor("#10B981") : Color.parseColor("#F59E0B"));
        permRow.setClickable(!snap.hasSecureSettings);

        batteryValue.setText(snap.batteryWhitelisted ? R.string.value_battery_ok : R.string.value_battery_restricted);
        batteryValue.setTextColor(snap.batteryWhitelisted ? Color.parseColor("#10B981") : Color.parseColor("#F59E0B"));
        batteryRow.setClickable(!snap.batteryWhitelisted);

        notifValue.setText(snap.notificationsEnabled ? R.string.value_notif_ok : R.string.value_notif_off);
        notifValue.setTextColor(snap.notificationsEnabled ? Color.parseColor("#10B981") : Color.parseColor("#F59E0B"));
        notifRow.setClickable(!snap.notificationsEnabled);

        rootValue.setText(snap.suAvailable ? R.string.value_root_detected : R.string.value_root_none);
        rootValue.setTextColor(snap.suAvailable ? Color.parseColor("#3B82F6") : textMuted);
    }

    private void renderCertCard(CertInspector.CertCheckResult cs) {
        if (cs == null) {
            certStatusValue.setText(R.string.value_cert_missing);
            certStatusValue.setTextColor(textMuted);
            certDetailValue.setText(R.string.value_cert_missing_detail);
            styleButton(certActionBtn, getString(R.string.btn_cert_settings), cardColor, textPrimary, borderColor, true);
            return;
        }

        String tag = !cs.hash.isEmpty() ? cs.hash : (!cs.subject.isEmpty() ? cs.subject : "Cap MITM CA");
        if (cs.installed && "system".equals(cs.store)) {
            certStatusValue.setText(R.string.value_cert_system);
            certStatusValue.setTextColor(Color.parseColor("#10B981"));
            certDetailValue.setText(getString(
                    cs.hasApexDir ? R.string.value_cert_system_apex_detail : R.string.value_cert_system_detail, tag));
            styleButton(certActionBtn, getString(R.string.btn_cert_details), cardColor, textPrimary, borderColor, true);
        } else if (cs.installed && "user".equals(cs.store)) {
            certStatusValue.setText(R.string.value_cert_user);
            certStatusValue.setTextColor(Color.parseColor("#3B82F6"));
            certDetailValue.setText(getString(R.string.value_cert_user_detail, tag));
            styleButton(certActionBtn, getString(R.string.btn_cert_details), cardColor, textPrimary, borderColor, true);
        } else if (cs.fingerprintMismatch) {
            certStatusValue.setText(R.string.value_cert_mismatch);
            certStatusValue.setTextColor(Color.parseColor("#F59E0B"));
            certDetailValue.setText(R.string.value_cert_mismatch_detail);
            if (cs.certFileReady) {
                styleButton(certActionBtn, getString(R.string.btn_reinstall_cert),
                        Color.parseColor("#F59E0B"), Color.parseColor("#0F172A"), Color.TRANSPARENT, true);
            } else {
                styleButton(certActionBtn, getString(R.string.btn_cert_details),
                        cardColor, Color.parseColor("#F59E0B"), Color.parseColor("#F59E0B"), true);
            }
        } else if (cs.legacySystemOnly) {
            certStatusValue.setText(R.string.value_cert_legacy_only);
            certStatusValue.setTextColor(Color.parseColor("#F59E0B"));
            certDetailValue.setText(R.string.value_cert_legacy_detail);
            styleButton(certActionBtn, getString(R.string.btn_cert_fix_guide),
                    Color.parseColor("#F59E0B"), Color.parseColor("#0F172A"), Color.TRANSPARENT, true);
        } else if (cs.certFileReady) {
            certStatusValue.setText(R.string.value_cert_ready);
            certStatusValue.setTextColor(Color.parseColor("#F59E0B"));
            certDetailValue.setText(getString(R.string.value_cert_ready_detail, tag));
            styleButton(certActionBtn, getString(R.string.btn_install_cert),
                    Color.parseColor("#3B82F6"), Color.WHITE, Color.TRANSPARENT, true);
        } else {
            certStatusValue.setText(R.string.value_cert_missing);
            certStatusValue.setTextColor(textMuted);
            certDetailValue.setText(R.string.value_cert_missing_detail);
            styleButton(certActionBtn, getString(R.string.btn_cert_settings),
                    cardColor, textPrimary, borderColor, true);
        }
    }

    private String formatCleanupTime(long ts) {
        Date d = new Date(ts);
        Calendar now = Calendar.getInstance();
        Calendar then = Calendar.getInstance();
        then.setTime(d);
        boolean sameDay = now.get(Calendar.YEAR) == then.get(Calendar.YEAR)
                && now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR);
        String pattern = sameDay ? "HH:mm:ss" : "MM-dd HH:mm";
        return new SimpleDateFormat(pattern, Locale.getDefault()).format(d);
    }

    // ==================== Proxy & Watchdog Actions ====================

    private void onStartWatchdogClicked() {
        UiSnapshot snap = latestSnapshot;
        if (snap == null || snap.globalProxy.isEmpty()) {
            return;
        }
        ProxyCleaner.HostPort hp = ProxyCleaner.parseProxyHostPort(snap.globalProxy);
        if (hp == null) {
            return;
        }
        try {
            Intent startIntent = new Intent(this, ProxyGuardService.class);
            startIntent.setAction(ProxyGuardService.ACTION_START);
            startIntent.putExtra(ProxyGuardService.EXTRA_PROXY_HOST, hp.host);
            startIntent.putExtra(ProxyGuardService.EXTRA_PROXY_PORT, hp.port);
            startIntent.putExtra(ProxyGuardService.EXTRA_MODE, "proxy");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent);
            } else {
                startService(startIntent);
            }
            Toast.makeText(this, getString(R.string.toast_watchdog_started, hp.host + ":" + hp.port), Toast.LENGTH_SHORT).show();
            requestRefresh(false, false);
        } catch (Throwable t) {
            String errMsg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            Toast.makeText(this, getString(R.string.toast_watchdog_start_failed, errMsg), Toast.LENGTH_LONG).show();
        }
    }

    private void onProxyActionClicked() {
        if (localCleanupBusy || serviceCleanupBusy || ProxyGuardService.isCleanupInProgress()) {
            return;
        }
        UiSnapshot snap = latestSnapshot;
        if (snap == null) {
            return;
        }
        boolean hasWork = snap.serviceRunning || !snap.globalProxy.isEmpty() || snap.staleVpn;
        if (!hasWork) {
            return;
        }

        if (ProxyGuardService.isServiceRunning()) {
            serviceCleanupBusy = true;
            renderSnapshot(snap);
            try {
                Intent stopIntent = new Intent(this, ProxyGuardService.class);
                stopIntent.setAction(ProxyGuardService.ACTION_RESTORE);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(stopIntent);
                } else {
                    startService(stopIntent);
                }
            } catch (Throwable t) {
                serviceCleanupBusy = false;
                Toast.makeText(this, R.string.toast_clean_failed, Toast.LENGTH_SHORT).show();
                requestRefresh(false, false);
            }
            return;
        }

        localCleanupBusy = true;
        renderSnapshot(snap);
        final String modeToClean = snap.staleVpn ? "vpn" : "proxy";
        final String redirPort = snap.redirPort;
        runIo(new Runnable() {
            @Override
            public void run() {
                final boolean ok = ProxyCleaner.cleanup(MainActivity.this, modeToClean, redirPort);
                GuardPrefs.recordCleanup(MainActivity.this, getString(R.string.reason_manual), ok);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        localCleanupBusy = false;
                        Toast.makeText(
                                MainActivity.this,
                                ok ? R.string.toast_cleaned : R.string.toast_clean_failed,
                                Toast.LENGTH_SHORT).show();
                        requestRefresh(false, false);
                    }
                });
            }
        });
    }

    // ==================== CA Certificate Actions ====================

    private void onCertActionClicked() {
        UiSnapshot snap = latestSnapshot;
        CertInspector.CertCheckResult cs = snap != null ? snap.certStatus : null;
        if (cs == null) {
            openCredentialSettings();
            return;
        }

        if (cs.installed) {
            showCertDetailsDialog(cs);
            return;
        }
        if (cs.legacySystemOnly) {
            showLegacyApexDialog(cs);
            return;
        }
        if (cs.fingerprintMismatch) {
            if (cs.certFileReady) {
                launchCertInstallAsync(pendingCertPath);
            } else {
                showCertDetailsDialog(cs);
            }
            return;
        }
        if (cs.certFileReady) {
            launchCertInstallAsync(pendingCertPath);
            return;
        }
        openCredentialSettings();
    }

    private void showCertDetailsDialog(final CertInspector.CertCheckResult cs) {
        StringBuilder msg = new StringBuilder();
        String storeText;
        if (cs.installed && "system".equals(cs.store)) {
            storeText = cs.hasApexDir ? "System CA (Android 14+ APEX Conscrypt)" : "System CA (/system)";
        } else if (cs.installed && "user".equals(cs.store)) {
            storeText = "User CA (AndroidCAStore)";
        } else if (cs.fingerprintMismatch) {
            storeText = "Fingerprint Mismatch";
        } else {
            storeText = cs.store;
        }
        msg.append("Store: ").append(storeText);
        if (!cs.subject.isEmpty()) {
            msg.append("\nSubject: ").append(cs.subject);
        }
        if (!cs.hash.isEmpty()) {
            msg.append("\nHash: ").append(cs.hash);
        }
        if (!cs.alias.isEmpty()) {
            msg.append("\nAlias: ").append(cs.alias);
        }
        if (!cs.fingerprint.isEmpty()) {
            msg.append("\n\nSHA-256:\n").append(cs.fingerprint);
        }
        if (cs.fingerprintMismatch && !cs.expectedFingerprint.isEmpty()) {
            msg.append("\n\nExpected SHA-256:\n").append(cs.expectedFingerprint);
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_cert_title)
                .setMessage(msg.toString())
                .setNegativeButton(R.string.dialog_close, null);

        if (!cs.fingerprint.isEmpty()) {
            builder.setPositiveButton(R.string.dialog_cert_copy_fp, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    copyToClipboard("CA SHA-256", cs.fingerprint);
                }
            });
        }
        if ("user".equals(cs.store) && cs.certFileReady) {
            builder.setNeutralButton(R.string.dialog_cert_reinstall, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    launchCertInstallAsync(pendingCertPath);
                }
            });
        } else {
            builder.setNeutralButton(R.string.dialog_cert_open_settings, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    openCredentialSettings();
                }
            });
        }
        if (!isFinishing() && !isDestroyed()) {
            builder.show();
        }
    }

    private void showLegacyApexDialog(final CertInspector.CertCheckResult cs) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_cert_legacy_title)
                .setMessage(R.string.dialog_cert_legacy_body)
                .setNegativeButton(R.string.dialog_close, null);
        if (cs.certFileReady) {
            builder.setPositiveButton(R.string.btn_install_cert, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    launchCertInstallAsync(pendingCertPath);
                }
            });
        }
        if (!isFinishing() && !isDestroyed()) {
            builder.show();
        }
    }

    private void openCredentialSettings() {
        try {
            startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS));
        } catch (Throwable t) {
            try {
                startActivity(new Intent(Settings.ACTION_SETTINGS));
            } catch (Throwable ignored) {
            }
        }
    }

    // ==================== Permissions & Environment Actions ====================

    private void onPermissionRowClicked() {
        UiSnapshot snap = latestSnapshot;
        if (snap != null && snap.hasSecureSettings) {
            return;
        }
        final String adbCmd = "adb shell pm grant " + getPackageName() + " android.permission.WRITE_SECURE_SETTINGS";
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_perm_title)
                .setMessage(getString(R.string.dialog_perm_body, adbCmd))
                .setPositiveButton(R.string.dialog_perm_copy, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        copyToClipboard("ADB Grant Command", adbCmd);
                    }
                })
                .setNegativeButton(R.string.dialog_close, null);

        if (snap != null && snap.suAvailable) {
            builder.setNeutralButton(R.string.dialog_perm_grant_root, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    grantSecureSettingsViaRootAsync();
                }
            });
        }
        if (!isFinishing() && !isDestroyed()) {
            builder.show();
        }
    }

    private void grantSecureSettingsViaRootAsync() {
        runIo(new Runnable() {
            @Override
            public void run() {
                final boolean ok = ProxyCleaner.grantWriteSecureSettingsViaRoot(MainActivity.this);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        Toast.makeText(
                                MainActivity.this,
                                ok ? R.string.toast_root_grant_ok : R.string.toast_root_grant_failed,
                                Toast.LENGTH_SHORT).show();
                        requestRefresh(false, false);
                    }
                });
            }
        });
    }

    private void onBatteryRowClicked() {
        UiSnapshot snap = latestSnapshot;
        if (snap != null && snap.batteryWhitelisted) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
                return;
            }
        } catch (Throwable ignored) {
        }
        openAppDetailsSettings();
    }

    private void openAppNotificationSettings() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Intent i = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
                i.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
                startActivity(i);
                return;
            }
        } catch (Throwable ignored) {
        }
        openAppDetailsSettings();
    }

    private void onNotifRowClicked() {
        UiSnapshot snap = latestSnapshot;
        if (snap != null && snap.notificationsEnabled) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, REQ_POST_NOTIFICATIONS);
            return;
        }
        openAppNotificationSettings();
    }

    private void openAppDetailsSettings() {
        try {
            Intent i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            i.setData(Uri.parse("package:" + getPackageName()));
            startActivity(i);
        } catch (Throwable ignored) {
        }
    }

    private void copyToClipboard(String label, String text) {
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText(label, text));
                Toast.makeText(this, R.string.toast_copied, Toast.LENGTH_SHORT).show();
            }
        } catch (Throwable ignored) {
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_POST_NOTIFICATIONS) {
            if (Build.VERSION.SDK_INT >= 33
                    && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED
                    && !shouldShowRequestPermissionRationale("android.permission.POST_NOTIFICATIONS")) {
                openAppNotificationSettings();
            }
            requestRefresh(false, false);
        }
    }

    // ==================== Intent Extras & KeyChain Flow ====================

    private void handleIntentExtras(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.hasExtra(EXTRA_CERT_PATH)) {
            pendingCertPath = intent.getStringExtra(EXTRA_CERT_PATH);
        }
        final String certHash = CertInspector.normalizeHash(intent.getStringExtra(EXTRA_CERT_HASH));
        final String certFp = intent.getStringExtra(EXTRA_CERT_FP);
        final String certB64 = intent.getStringExtra(EXTRA_CERT_B64);
        final boolean autoInstall = intent.getBooleanExtra(EXTRA_INSTALL_CERT, false);
        if (autoInstall) {
            intent.removeExtra(EXTRA_INSTALL_CERT);
        }

        if (certHash.isEmpty() && (certFp == null || certFp.trim().isEmpty()) && certB64 == null && !autoInstall) {
            return;
        }

        final String pathSnapshot = pendingCertPath;
        runIo(new Runnable() {
            @Override
            public void run() {
                if (!certHash.isEmpty() || (certFp != null && !certFp.trim().isEmpty())) {
                    GuardPrefs.saveCertMeta(MainActivity.this, certHash, certFp, null);
                }
                byte[] decodedCertBytes = null;
                if (certB64 != null) {
                    String trimmedB64 = certB64.trim();
                    if (!trimmedB64.isEmpty() && trimmedB64.length() <= MAX_CERT_B64_CHARS) {
                        try {
                            byte[] raw = Base64.decode(trimmedB64, Base64.DEFAULT);
                            if (raw != null && raw.length > 0 && raw.length <= MAX_CERT_BYTES) {
                                X509Certificate parsed = CertInspector.parseCertBytes(raw);
                                if (parsed != null) {
                                    decodedCertBytes = raw;
                                    ProxyCleaner.savePrivateCertBytes(MainActivity.this, decodedCertBytes);
                                    GuardPrefs.saveCertMeta(
                                            MainActivity.this,
                                            CertInspector.computeSubjectHashOld(parsed),
                                            CertInspector.computeSha256Fingerprint(parsed),
                                            CertInspector.extractCommonName(parsed));
                                }
                            }
                        } catch (Throwable ignored) {
                            decodedCertBytes = null;
                        }
                    }
                }
                final byte[] certToInstall = decodedCertBytes;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        requestRefresh(false, false);
                        if (autoInstall) {
                            if (certToInstall != null && certToInstall.length > 0) {
                                launchCertInstallBytes(certToInstall);
                            } else {
                                launchCertInstallAsync(pathSnapshot);
                            }
                        }
                    }
                });
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_INSTALL_CERT) {
            final boolean userConfirmed = (resultCode == Activity.RESULT_OK);
            requestRefresh(false, userConfirmed);
            if (userConfirmed) {
                // Android 11-14 KeyChain occasionally persists User CA asynchronously ~200-400ms after returning.
                mainHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        if (!isFinishing() && !isDestroyed()) {
                            UiSnapshot snap = latestSnapshot;
                            boolean alreadyInstalled = snap != null && snap.certStatus != null && snap.certStatus.installed;
                            if (!alreadyInstalled) {
                                requestRefresh(false, true);
                            }
                        }
                    }
                }, 450L);
            }
        }
    }

    private void launchCertInstallAsync(final String preferredPath) {
        runIo(new Runnable() {
            @Override
            public void run() {
                File certFile = ProxyCleaner.findCertFile(MainActivity.this, preferredPath);
                byte[] bytes = null;
                String errMsg = null;
                if (certFile != null) {
                    try {
                        bytes = readAllBytes(certFile);
                    } catch (Throwable t) {
                        errMsg = t.getMessage();
                    }
                }
                final byte[] finalBytes = bytes;
                final String finalErr = errMsg;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        if (finalErr != null) {
                            Toast.makeText(MainActivity.this, getString(R.string.toast_cert_failed, finalErr), Toast.LENGTH_LONG).show();
                            return;
                        }
                        if (finalBytes == null || finalBytes.length == 0) {
                            Toast.makeText(MainActivity.this, R.string.toast_cert_not_found, Toast.LENGTH_LONG).show();
                            return;
                        }
                        launchCertInstallBytes(finalBytes);
                    }
                });
            }
        });
    }

    private void launchCertInstallBytes(byte[] certBytes) {
        try {
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, certBytes);
            installIntent.putExtra(KeyChain.EXTRA_NAME, "Cap MITM CA");
            startActivityForResult(installIntent, REQ_INSTALL_CERT);
            Toast.makeText(this, R.string.toast_cert_launched, Toast.LENGTH_SHORT).show();
        } catch (Throwable t) {
            String errMsg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            Toast.makeText(this, getString(R.string.toast_cert_failed, errMsg), Toast.LENGTH_LONG).show();
        }
    }

    private static byte[] readAllBytes(File file) throws Exception {
        if (file.length() > MAX_READ_BYTES) {
            throw new java.io.IOException("certificate file exceeds 64 KB limit");
        }
        InputStream in = new FileInputStream(file);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int total = 0;
            int n;
            while ((n = in.read(buf)) >= 0) {
                total += n;
                if (total > MAX_READ_BYTES) {
                    throw new java.io.IOException("certificate file exceeds 64 KB limit");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } finally {
            in.close();
        }
    }

    private GradientDrawable roundedRect(int fillColor, int strokeColor, int radiusPx, int strokeWidthPx) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setCornerRadius(radiusPx);
        d.setColor(fillColor);
        if (strokeWidthPx > 0) {
            d.setStroke(strokeWidthPx, strokeColor);
        }
        return d;
    }

    private int dp(int v) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics()));
    }
}
