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
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.security.KeyChain;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 2-Tab dark/light-aware workbench for Cap Guard:
 *  - Tab 1 (Guard): Proxy watchdog, CA certificate trust inspector, permissions & environment.
 *  - Tab 2 (Traffic): Live in-app MITM proxy traffic viewer backed by Cap's direct companion API.
 *
 * All blocking inspections and HTTP traffic calls run on dedicated single-thread background
 * executors with generation tracking so UI remains responsive and never applies stale snapshots.
 */
public class MainActivity extends Activity {
    public static final String EXTRA_INSTALL_CERT = "install_cert";
    public static final String EXTRA_CERT_PATH = "cert_path";
    public static final String EXTRA_CERT_B64 = "cert_b64";
    public static final String EXTRA_CERT_HASH = "cert_hash";
    public static final String EXTRA_CERT_FP = "cert_fp";
    public static final String EXTRA_API_TOKEN = "api_token";

    private static final int REQ_INSTALL_CERT = 2001;
    private static final int REQ_POST_NOTIFICATIONS = 2002;
    private static final int MAX_CERT_B64_CHARS = 65536;
    private static final int MAX_CERT_BYTES = 48 * 1024;
    private static final int MAX_READ_BYTES = 64 * 1024;

    private static final int TAB_GUARD = 0;
    private static final int TAB_TRAFFIC = 1;

    private static final int CHIP_ALL = 0;
    private static final int CHIP_GET = 1;
    private static final int CHIP_POST = 2;
    private static final int CHIP_ERRORS = 3;
    private static final int CHIP_HTTPS = 4;

    private static final int DETAIL_TAB_OVERVIEW = 0;
    private static final int DETAIL_TAB_REQUEST = 1;
    private static final int DETAIL_TAB_RESPONSE = 2;

    private static final long TRAFFIC_POLL_INTERVAL_MS = 1500L;
    private static final long SEARCH_DEBOUNCE_MS = 250L;
    private static final int DEFAULT_FLOW_LIMIT = 80;
    private static final int ERROR_FILTER_FLOW_LIMIT = 200;

    private final ExecutorService ioExecutor = Executors.newSingleThreadExecutor();
    private final ExecutorService trafficExecutor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicInteger refreshGen = new AtomicInteger(0);
    private final AtomicInteger trafficGen = new AtomicInteger(0);
    private final AtomicInteger detailGen = new AtomicInteger(0);

    // Theme palette
    private boolean isDarkTheme;
    private int bgColor;
    private int surfaceColor;
    private int cardColor;
    private int borderColor;
    private int dividerColor;
    private int textPrimary;
    private int textMuted;
    private int disabledBg;
    private int disabledText;
    private int accentColor;

    // Top Header & 2-Tab Switcher
    private TextView statusBadgeView;
    private TextView tabGuardBtn;
    private LinearLayout tabTrafficBtn;
    private TextView tabTrafficLabel;
    private TextView tabTrafficBadge;
    private ScrollView guardTabScroll;
    private LinearLayout trafficTabLayout;

    // Guard Tab — Card 1: Proxy & Watchdog
    private TextView systemProxyValue;
    private TextView watchdogValue;
    private LinearLayout modeRowContainer;
    private View modeRowDivider;
    private TextView modeValue;
    private TextView lastCleanupValue;
    private Button startWatchdogBtn;
    private Button proxyActionBtn;

    // Guard Tab — Card 2: CA Certificate
    private TextView certStatusValue;
    private TextView certDetailValue;
    private Button certActionBtn;

    // Guard Tab — Card 3: Permissions & Environment
    private LinearLayout permRow;
    private TextView permissionValue;
    private LinearLayout batteryRow;
    private TextView batteryValue;
    private LinearLayout notifRow;
    private TextView notifValue;
    private TextView rootValue;

    // Guard Tab — Bottom refresh
    private Button refreshBtn;

    // Traffic Tab Views
    private View trafficStatusDot;
    private TextView trafficStatusText;
    private TextView trafficPauseBtn;
    private TextView trafficClearBtn;
    private TextView trafficConfigBtn;
    private TextView metricFlowsVal;
    private TextView metricRpsVal;
    private TextView metricBytesVal;
    private EditText trafficSearchInput;
    private TextView trafficSearchClearBtn;
    private TextView[] filterChips;
    private ListView trafficListView;
    private TrafficAdapter trafficAdapter;
    private LinearLayout trafficEmptyContainer;
    private TextView trafficEmptyTitle;
    private TextView trafficEmptyHint;
    private Button trafficEmptyActionBtn;

    // Live Guard state
    private String pendingCertPath;
    private UiSnapshot latestSnapshot;
    private boolean localCleanupBusy = false;
    private boolean serviceCleanupBusy = false;
    private boolean refreshBusy = false;
    private boolean pendingManualToast = false;

    // Live Traffic state
    private boolean isResumed = false;
    private int activeTab = TAB_GUARD;
    private boolean trafficPaused = false;
    private boolean trafficPollInFlight = false;
    private boolean trafficClearBusy = false;
    private int selectedChip = CHIP_ALL;
    private String searchQuery = "";
    private String lastResolvedEndpoint = "";
    private TrafficClient.FlowsResult latestTrafficResult;
    private AlertDialog activeDialog;

    private final Runnable trafficPollRunnable = new Runnable() {
        @Override
        public void run() {
            if (activeTab == TAB_TRAFFIC && isResumed && !trafficPaused) {
                executeTrafficPoll(false);
            }
        }
    };

    private final Runnable searchDebounceRunnable = new Runnable() {
        @Override
        public void run() {
            if (activeTab == TAB_TRAFFIC && isResumed) {
                triggerTrafficPollNow(true);
            }
        }
    };

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
                String detail = intent.getStringExtra(ProxyGuardService.EXTRA_CLEANUP_DETAIL);
                if (ok) {
                    Toast.makeText(MainActivity.this, R.string.toast_cleaned, Toast.LENGTH_SHORT).show();
                } else {
                    String msg = (detail != null && !detail.isEmpty())
                            ? detail
                            : getString(R.string.toast_clean_failed);
                    Toast.makeText(MainActivity.this, msg, Toast.LENGTH_LONG).show();
                }
            }
            requestRefresh(false, false);
            if (activeTab == TAB_TRAFFIC && isResumed && !trafficPaused) {
                triggerTrafficPollNow(false);
            }
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
        if (activeTab == TAB_TRAFFIC && isResumed && !trafficPaused) {
            triggerTrafficPollNow(false);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        isResumed = true;
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
        if (activeTab == TAB_TRAFFIC && !trafficPaused) {
            triggerTrafficPollNow(false);
        }
    }

    @Override
    protected void onPause() {
        isResumed = false;
        stopTrafficPolling();
        try {
            unregisterReceiver(statusReceiver);
        } catch (Throwable ignored) {
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        isResumed = false;
        stopTrafficPolling();
        dismissActiveDialog();
        mainHandler.removeCallbacksAndMessages(null);
        ioExecutor.shutdownNow();
        trafficExecutor.shutdownNow();
        super.onDestroy();
    }

    private void initPalette() {
        bgColor = isDarkTheme ? Color.parseColor("#0B0F17") : Color.parseColor("#F4F6FA");
        surfaceColor = isDarkTheme ? Color.parseColor("#0F172A") : Color.parseColor("#F8FAFC");
        cardColor = isDarkTheme ? Color.parseColor("#131A27") : Color.parseColor("#FFFFFF");
        borderColor = isDarkTheme ? Color.parseColor("#243045") : Color.parseColor("#E2E8F0");
        dividerColor = isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#EEF2F6");
        textPrimary = isDarkTheme ? Color.parseColor("#F1F5F9") : Color.parseColor("#0F172A");
        textMuted = isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#64748B");
        disabledBg = isDarkTheme ? Color.parseColor("#1A2233") : Color.parseColor("#E2E8F0");
        disabledText = isDarkTheme ? Color.parseColor("#64748B") : Color.parseColor("#94A3B8");
        accentColor = Color.parseColor("#2563EB");
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

    // ==================== Root 2-Tab Layout ====================

    private View buildContentView() {
        final LinearLayout rootContainer = new LinearLayout(this);
        rootContainer.setOrientation(LinearLayout.VERTICAL);
        rootContainer.setBackgroundColor(bgColor);
        rootContainer.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.MATCH_PARENT));

        // Edge-to-edge safe insets for Android 14/15 and gesture nav devices
        rootContainer.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
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
                rootContainer.setPadding(left, top, right, bottom);
                return insets;
            }
        });

        // Compact Header
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(16), dp(14), dp(16), dp(10));
        rootContainer.addView(header, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.ic_launcher);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(38), dp(38));
        iconLp.rightMargin = dp(10);
        header.addView(icon, iconLp);

        LinearLayout titleCol = new LinearLayout(this);
        titleCol.setOrientation(LinearLayout.VERTICAL);
        header.addView(titleCol, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextColor(textPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 18);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        titleCol.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(getString(R.string.app_subtitle, resolveVersionName()));
        subtitle.setTextColor(textMuted);
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        titleCol.addView(subtitle);

        statusBadgeView = new TextView(this);
        statusBadgeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        statusBadgeView.setTypeface(Typeface.DEFAULT_BOLD);
        statusBadgeView.setPadding(dp(10), dp(4), dp(10), dp(4));
        LinearLayout.LayoutParams badgeLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        badgeLp.leftMargin = dp(8);
        header.addView(statusBadgeView, badgeLp);

        // 2-Tab Top Segmented Switcher
        rootContainer.addView(buildTabSwitcher());

        // Content switcher container (ScrollView for Guard, non-scrolling LinearLayout+ListView for Traffic)
        FrameLayout tabContent = new FrameLayout(this);
        rootContainer.addView(tabContent, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        guardTabScroll = buildGuardTab();
        tabContent.addView(guardTabScroll, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        trafficTabLayout = buildTrafficTab();
        trafficTabLayout.setVisibility(View.GONE);
        tabContent.addView(trafficTabLayout, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        updateTabVisuals();
        return rootContainer;
    }

    private View buildTabSwitcher() {
        LinearLayout track = new LinearLayout(this);
        track.setOrientation(LinearLayout.HORIZONTAL);
        track.setPadding(dp(3), dp(3), dp(3), dp(3));
        track.setBackground(roundedRect(cardColor, borderColor, dp(10), dp(1)));
        LinearLayout.LayoutParams trackLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        trackLp.leftMargin = dp(16);
        trackLp.rightMargin = dp(16);
        trackLp.bottomMargin = dp(10);
        track.setLayoutParams(trackLp);

        tabGuardBtn = new TextView(this);
        tabGuardBtn.setText(R.string.tab_guard);
        tabGuardBtn.setGravity(Gravity.CENTER);
        tabGuardBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tabGuardBtn.setTypeface(Typeface.DEFAULT_BOLD);
        tabGuardBtn.setPadding(dp(12), dp(8), dp(12), dp(8));
        tabGuardBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchToTab(TAB_GUARD);
            }
        });
        track.addView(tabGuardBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        tabTrafficBtn = new LinearLayout(this);
        tabTrafficBtn.setOrientation(LinearLayout.HORIZONTAL);
        tabTrafficBtn.setGravity(Gravity.CENTER);
        tabTrafficBtn.setPadding(dp(12), dp(8), dp(12), dp(8));
        tabTrafficBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchToTab(TAB_TRAFFIC);
            }
        });

        tabTrafficLabel = new TextView(this);
        tabTrafficLabel.setText(R.string.tab_traffic);
        tabTrafficLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        tabTrafficLabel.setTypeface(Typeface.DEFAULT_BOLD);
        tabTrafficBtn.addView(tabTrafficLabel);

        tabTrafficBadge = new TextView(this);
        tabTrafficBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        tabTrafficBadge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        tabTrafficBadge.setPadding(dp(6), dp(1), dp(6), dp(1));
        tabTrafficBadge.setVisibility(View.GONE);
        LinearLayout.LayoutParams tbLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        tbLp.leftMargin = dp(6);
        tabTrafficBtn.addView(tabTrafficBadge, tbLp);

        track.addView(tabTrafficBtn, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        return track;
    }

    private void switchToTab(int targetTab) {
        if (activeTab == targetTab) {
            return;
        }
        activeTab = targetTab;
        updateTabVisuals();
        if (activeTab == TAB_GUARD) {
            guardTabScroll.setVisibility(View.VISIBLE);
            trafficTabLayout.setVisibility(View.GONE);
            stopTrafficPolling();
            requestRefresh(false, false);
        } else {
            guardTabScroll.setVisibility(View.GONE);
            trafficTabLayout.setVisibility(View.VISIBLE);
            if (!trafficPaused && isResumed) {
                triggerTrafficPollNow(false);
            } else if (latestTrafficResult == null && isResumed) {
                renderTrafficState();
            }
        }
    }

    private void updateTabVisuals() {
        boolean guardActive = (activeTab == TAB_GUARD);
        int activeFill = isDarkTheme ? Color.parseColor("#1E293B") : accentColor;
        int activeStroke = isDarkTheme ? Color.parseColor("#334155") : Color.TRANSPARENT;
        int activeText = Color.WHITE;

        if (guardActive) {
            tabGuardBtn.setBackground(roundedRect(activeFill, activeStroke, dp(8), activeStroke == Color.TRANSPARENT ? 0 : dp(1)));
            tabGuardBtn.setTextColor(activeText);
            tabTrafficBtn.setBackground(null);
            tabTrafficLabel.setTextColor(textMuted);
        } else {
            tabGuardBtn.setBackground(null);
            tabGuardBtn.setTextColor(textMuted);
            tabTrafficBtn.setBackground(roundedRect(activeFill, activeStroke, dp(8), activeStroke == Color.TRANSPARENT ? 0 : dp(1)));
            tabTrafficLabel.setTextColor(activeText);
        }

        // Keep badge readable in both active and inactive tab states
        if (guardActive) {
            tabTrafficBadge.setTextColor(isDarkTheme ? Color.parseColor("#38BDF8") : Color.parseColor("#0284C7"));
            tabTrafficBadge.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#0C2D48") : Color.parseColor("#E0F2FE"),
                    Color.TRANSPARENT, dp(99), 0));
        } else {
            tabTrafficBadge.setTextColor(Color.WHITE);
            tabTrafficBadge.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#0EA5E9") : Color.parseColor("#1D4ED8"),
                    Color.TRANSPARENT, dp(99), 0));
        }
    }

    private void updateTrafficCountBadge(int count) {
        if (count > 0) {
            tabTrafficBadge.setText(count > 999 ? "999+" : String.valueOf(count));
            tabTrafficBadge.setVisibility(View.VISIBLE);
        } else {
            tabTrafficBadge.setVisibility(View.GONE);
        }
    }

    // ==================== Tab 1: Guard Layout ====================

    private ScrollView buildGuardTab() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setClipToPadding(false);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(2), dp(16), dp(24));
        scroll.addView(root);

        // ===== Card 1: Proxy & Watchdog =====
        LinearLayout proxyCard = addCard(root, R.string.section_proxy, dp(4));
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

    // ==================== Tab 2: Live Traffic Layout ====================

    private LinearLayout buildTrafficTab() {
        LinearLayout container = new LinearLayout(this);
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(dp(16), dp(2), dp(16), 0);

        // 1. Live Connection & Metrics Bar
        LinearLayout metricsCard = new LinearLayout(this);
        metricsCard.setOrientation(LinearLayout.VERTICAL);
        metricsCard.setPadding(dp(12), dp(10), dp(12), dp(10));
        metricsCard.setBackground(roundedRect(cardColor, borderColor, dp(12), dp(1)));
        container.addView(metricsCard, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        // Status + Action buttons row
        LinearLayout statusRow = new LinearLayout(this);
        statusRow.setOrientation(LinearLayout.HORIZONTAL);
        statusRow.setGravity(Gravity.CENTER_VERTICAL);
        metricsCard.addView(statusRow, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        trafficStatusDot = new View(this);
        trafficStatusDot.setBackground(roundedRect(Color.parseColor("#64748B"), Color.TRANSPARENT, dp(99), 0));
        LinearLayout.LayoutParams dotLp = new LinearLayout.LayoutParams(dp(8), dp(8));
        dotLp.rightMargin = dp(7);
        statusRow.addView(trafficStatusDot, dotLp);

        trafficStatusText = new TextView(this);
        trafficStatusText.setText(R.string.traffic_status_connecting);
        trafficStatusText.setTextColor(textPrimary);
        trafficStatusText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        trafficStatusText.setTypeface(Typeface.DEFAULT_BOLD);
        trafficStatusText.setSingleLine(true);
        trafficStatusText.setEllipsize(TextUtils.TruncateAt.END);
        statusRow.addView(trafficStatusText, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        trafficPauseBtn = createCompactPillButton(getString(R.string.traffic_btn_pause));
        trafficPauseBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                toggleTrafficPause();
            }
        });
        LinearLayout.LayoutParams pLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        pLp.leftMargin = dp(6);
        statusRow.addView(trafficPauseBtn, pLp);

        trafficClearBtn = createCompactPillButton(getString(R.string.traffic_btn_clear));
        trafficClearBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onClearTrafficClicked();
            }
        });
        LinearLayout.LayoutParams cLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cLp.leftMargin = dp(5);
        statusRow.addView(trafficClearBtn, cLp);

        trafficConfigBtn = createCompactPillButton(getString(R.string.traffic_btn_config));
        trafficConfigBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openTrafficConfigDialog();
            }
        });
        LinearLayout.LayoutParams cfgLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cfgLp.leftMargin = dp(5);
        statusRow.addView(trafficConfigBtn, cfgLp);

        // Metrics row: Total Flows | Req/s | Volume
        View metricDiv = new View(this);
        metricDiv.setBackgroundColor(dividerColor);
        LinearLayout.LayoutParams mdLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, dp(1));
        mdLp.topMargin = dp(8);
        mdLp.bottomMargin = dp(8);
        metricsCard.addView(metricDiv, mdLp);

        LinearLayout metricsRow = new LinearLayout(this);
        metricsRow.setOrientation(LinearLayout.HORIZONTAL);
        metricsCard.addView(metricsRow, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        metricFlowsVal = addMetricCell(metricsRow, R.string.traffic_metric_flows, "0");
        metricRpsVal = addMetricCell(metricsRow, R.string.traffic_metric_rps, "0.0/s");
        metricBytesVal = addMetricCell(metricsRow, R.string.traffic_metric_bytes, "0 B");

        // 2. Search Bar
        LinearLayout searchBox = new LinearLayout(this);
        searchBox.setOrientation(LinearLayout.HORIZONTAL);
        searchBox.setGravity(Gravity.CENTER_VERTICAL);
        searchBox.setPadding(dp(12), dp(2), dp(8), dp(2));
        searchBox.setBackground(roundedRect(surfaceColor, borderColor, dp(10), dp(1)));
        LinearLayout.LayoutParams searchBoxLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        searchBoxLp.topMargin = dp(10);
        container.addView(searchBox, searchBoxLp);

        trafficSearchInput = new EditText(this);
        trafficSearchInput.setHint(R.string.traffic_search_hint);
        trafficSearchInput.setHintTextColor(textMuted);
        trafficSearchInput.setTextColor(textPrimary);
        trafficSearchInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        trafficSearchInput.setSingleLine(true);
        trafficSearchInput.setImeOptions(EditorInfo.IME_ACTION_SEARCH);
        trafficSearchInput.setBackground(null);
        trafficSearchInput.setPadding(0, dp(8), dp(6), dp(8));
        trafficSearchInput.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {}

            @Override
            public void afterTextChanged(Editable s) {
                String next = s != null ? s.toString().trim() : "";
                trafficSearchClearBtn.setVisibility(next.isEmpty() ? View.GONE : View.VISIBLE);
                if (!next.equals(searchQuery)) {
                    searchQuery = next;
                    mainHandler.removeCallbacks(searchDebounceRunnable);
                    mainHandler.postDelayed(searchDebounceRunnable, SEARCH_DEBOUNCE_MS);
                }
            }
        });
        searchBox.addView(trafficSearchInput, new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        trafficSearchClearBtn = new TextView(this);
        trafficSearchClearBtn.setText("✕");
        trafficSearchClearBtn.setTextColor(textMuted);
        trafficSearchClearBtn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        trafficSearchClearBtn.setPadding(dp(8), dp(4), dp(8), dp(4));
        trafficSearchClearBtn.setVisibility(View.GONE);
        trafficSearchClearBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                trafficSearchInput.setText("");
            }
        });
        searchBox.addView(trafficSearchClearBtn);

        // 3. Horizontal Filter Chips
        HorizontalScrollView chipScroll = new HorizontalScrollView(this);
        chipScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout.LayoutParams chipScrollLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        chipScrollLp.topMargin = dp(8);
        container.addView(chipScroll, chipScrollLp);

        LinearLayout chipRow = new LinearLayout(this);
        chipRow.setOrientation(LinearLayout.HORIZONTAL);
        chipScroll.addView(chipRow);

        int[] chipLabels = {
                R.string.traffic_chip_all,
                R.string.traffic_chip_get,
                R.string.traffic_chip_post,
                R.string.traffic_chip_errors,
                R.string.traffic_chip_https
        };
        filterChips = new TextView[chipLabels.length];
        for (int i = 0; i < chipLabels.length; i++) {
            final int chipIdx = i;
            TextView chip = new TextView(this);
            chip.setText(chipLabels[i]);
            chip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            chip.setTypeface(Typeface.DEFAULT_BOLD);
            chip.setPadding(dp(12), dp(6), dp(12), dp(6));
            chip.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    if (selectedChip != chipIdx) {
                        selectedChip = chipIdx;
                        updateFilterChipStyles();
                        triggerTrafficPollNow(true);
                    }
                }
            });
            LinearLayout.LayoutParams chipLp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            if (i > 0) {
                chipLp.leftMargin = dp(6);
            }
            chipRow.addView(chip, chipLp);
            filterChips[i] = chip;
        }
        updateFilterChipStyles();

        // 4. Scrollable Live ListView + Empty/Error Overlay (NEVER nested inside ScrollView)
        FrameLayout listArea = new FrameLayout(this);
        LinearLayout.LayoutParams listAreaLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        listAreaLp.topMargin = dp(8);
        container.addView(listArea, listAreaLp);

        trafficAdapter = new TrafficAdapter(this, isDarkTheme);
        trafficListView = new ListView(this);
        trafficListView.setAdapter(trafficAdapter);
        trafficListView.setDivider(new ColorDrawable(Color.TRANSPARENT));
        trafficListView.setDividerHeight(0);
        trafficListView.setSelector(new ColorDrawable(Color.TRANSPARENT));
        trafficListView.setClipToPadding(false);
        trafficListView.setPadding(0, dp(2), 0, dp(16));
        trafficListView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                TrafficClient.FlowSummary flow = trafficAdapter.getItem(position);
                if (flow != null) {
                    openFlowDetailDialog(flow);
                }
            }
        });
        listArea.addView(trafficListView, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        trafficEmptyContainer = new LinearLayout(this);
        trafficEmptyContainer.setOrientation(LinearLayout.VERTICAL);
        trafficEmptyContainer.setGravity(Gravity.CENTER);
        trafficEmptyContainer.setPadding(dp(20), dp(24), dp(20), dp(24));
        trafficEmptyContainer.setVisibility(View.GONE);

        trafficEmptyTitle = new TextView(this);
        trafficEmptyTitle.setTextColor(textPrimary);
        trafficEmptyTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        trafficEmptyTitle.setTypeface(Typeface.DEFAULT_BOLD);
        trafficEmptyTitle.setGravity(Gravity.CENTER);
        trafficEmptyContainer.addView(trafficEmptyTitle);

        trafficEmptyHint = new TextView(this);
        trafficEmptyHint.setTextColor(textMuted);
        trafficEmptyHint.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        trafficEmptyHint.setGravity(Gravity.CENTER);
        trafficEmptyHint.setLineSpacing(dp(3), 1f);
        LinearLayout.LayoutParams hintLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        hintLp.topMargin = dp(6);
        trafficEmptyContainer.addView(trafficEmptyHint, hintLp);

        trafficEmptyActionBtn = createActionButton(
                getString(R.string.traffic_btn_open_config),
                accentColor,
                Color.WHITE,
                Color.TRANSPARENT);
        LinearLayout.LayoutParams eaLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        eaLp.topMargin = dp(14);
        trafficEmptyActionBtn.setVisibility(View.GONE);
        trafficEmptyContainer.addView(trafficEmptyActionBtn, eaLp);

        listArea.addView(trafficEmptyContainer, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT));

        return container;
    }

    private TextView createCompactPillButton(String label) {
        TextView btn = new TextView(this);
        btn.setText(label);
        btn.setTextColor(textPrimary);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        btn.setTypeface(Typeface.DEFAULT_BOLD);
        btn.setPadding(dp(9), dp(5), dp(9), dp(5));
        btn.setBackground(roundedRect(surfaceColor, borderColor, dp(7), dp(1)));
        return btn;
    }

    private TextView addMetricCell(LinearLayout parent, int labelRes, String initialVal) {
        LinearLayout cell = new LinearLayout(this);
        cell.setOrientation(LinearLayout.VERTICAL);
        cell.setGravity(Gravity.CENTER_HORIZONTAL);

        TextView val = new TextView(this);
        val.setText(initialVal);
        val.setTextColor(textPrimary);
        val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        val.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        cell.addView(val);

        TextView lbl = new TextView(this);
        lbl.setText(labelRes);
        lbl.setTextColor(textMuted);
        lbl.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        LinearLayout.LayoutParams lLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lLp.topMargin = dp(2);
        cell.addView(lbl, lLp);

        parent.addView(cell, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        return val;
    }

    private void updateFilterChipStyles() {
        if (filterChips == null) {
            return;
        }
        for (int i = 0; i < filterChips.length; i++) {
            boolean active = (i == selectedChip);
            TextView chip = filterChips[i];
            if (active) {
                chip.setTextColor(Color.WHITE);
                chip.setBackground(roundedRect(accentColor, Color.TRANSPARENT, dp(99), 0));
            } else {
                chip.setTextColor(textMuted);
                chip.setBackground(roundedRect(cardColor, borderColor, dp(99), dp(1)));
            }
        }
    }

    // ==================== Smart Traffic Polling & Rendering ====================

    private void stopTrafficPolling() {
        mainHandler.removeCallbacks(trafficPollRunnable);
        mainHandler.removeCallbacks(searchDebounceRunnable);
        trafficGen.incrementAndGet();
        trafficPollInFlight = false;
    }

    private void triggerTrafficPollNow(boolean oneShotEvenIfPaused) {
        mainHandler.removeCallbacks(trafficPollRunnable);
        trafficGen.incrementAndGet();
        trafficPollInFlight = false;
        executeTrafficPoll(oneShotEvenIfPaused);
    }

    private void executeTrafficPoll(final boolean oneShotEvenIfPaused) {
        if (isFinishing() || isDestroyed() || !isResumed || activeTab != TAB_TRAFFIC) {
            return;
        }
        if (trafficPaused && !oneShotEvenIfPaused) {
            return;
        }
        if (trafficPollInFlight) {
            return;
        }

        final int gen = trafficGen.get();
        final int chipSnapshot = selectedChip;
        final String searchSnapshot = searchQuery;
        trafficPollInFlight = true;

        runTrafficIo(new Runnable() {
            @Override
            public void run() {
                Context appCtx = getApplicationContext();
                final String endpoint = resolveTrafficEndpoint(appCtx);
                final String token = GuardPrefs.getApiToken(appCtx);

                String methodFilter = "";
                String schemeFilter = "";
                int limit = DEFAULT_FLOW_LIMIT;
                if (chipSnapshot == CHIP_GET) {
                    methodFilter = "GET";
                } else if (chipSnapshot == CHIP_POST) {
                    methodFilter = "POST";
                } else if (chipSnapshot == CHIP_HTTPS) {
                    schemeFilter = "https";
                } else if (chipSnapshot == CHIP_ERRORS) {
                    // Fetch full ring window and filter 4xx/5xx/error locally so every error status is guaranteed visible.
                    limit = ERROR_FILTER_FLOW_LIMIT;
                }

                final TrafficClient.FlowsResult result = TrafficClient.fetchFlows(
                        endpoint, token, limit, 0L, methodFilter, searchSnapshot, "", schemeFilter);

                if (result.ok && chipSnapshot == CHIP_ERRORS) {
                    List<TrafficClient.FlowSummary> errorsOnly = new ArrayList<TrafficClient.FlowSummary>();
                    for (TrafficClient.FlowSummary f : result.flows) {
                        boolean isErr = f.status >= 400 || f.status <= 0 || (f.error != null && !f.error.isEmpty());
                        if (isErr) {
                            errorsOnly.add(f);
                        }
                    }
                    result.flows = errorsOnly;
                }

                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed() || trafficGen.get() != gen) {
                            return;
                        }
                        trafficPollInFlight = false;
                        lastResolvedEndpoint = endpoint;
                        latestTrafficResult = result;
                        renderTrafficState();

                        if (activeTab == TAB_TRAFFIC && isResumed && !trafficPaused && trafficGen.get() == gen) {
                            mainHandler.removeCallbacks(trafficPollRunnable);
                            mainHandler.postDelayed(trafficPollRunnable, TRAFFIC_POLL_INTERVAL_MS);
                        }
                    }
                });
            }
        });
    }

    private String resolveTrafficEndpoint(Context appCtx) {
        return TrafficClient.resolveEndpoint(
                GuardPrefs.getCustomTrafficEndpoint(appCtx),
                ProxyCleaner.getGlobalHttpProxy(appCtx),
                ProxyGuardService.getRunningHost(),
                ProxyGuardService.getRunningPort(),
                GuardPrefs.getProxyHost(appCtx),
                GuardPrefs.getProxyPort(appCtx));
    }

    private String resolveAutoTrafficEndpoint(Context appCtx) {
        return TrafficClient.resolveAutoEndpoint(
                ProxyCleaner.getGlobalHttpProxy(appCtx),
                ProxyGuardService.getRunningHost(),
                ProxyGuardService.getRunningPort(),
                GuardPrefs.getProxyHost(appCtx),
                GuardPrefs.getProxyPort(appCtx));
    }

    private void renderTrafficState() {
        // Pause/Resume button state
        trafficPauseBtn.setText(trafficPaused ? R.string.traffic_btn_resume : R.string.traffic_btn_pause);
        if (trafficPaused) {
            trafficPauseBtn.setTextColor(Color.parseColor("#F59E0B"));
            trafficPauseBtn.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#31230D") : Color.parseColor("#FEF3C7"),
                    Color.parseColor("#F59E0B"), dp(7), dp(1)));
        } else {
            trafficPauseBtn.setTextColor(textPrimary);
            trafficPauseBtn.setBackground(roundedRect(surfaceColor, borderColor, dp(7), dp(1)));
        }

        TrafficClient.FlowsResult res = latestTrafficResult;
        String epDisplay = !lastResolvedEndpoint.isEmpty() ? lastResolvedEndpoint : getString(R.string.value_none);

        if (res == null) {
            setTrafficStatus(Color.parseColor("#64748B"), getString(
                    trafficPaused ? R.string.traffic_status_paused : R.string.traffic_status_connecting, epDisplay));
            return;
        }

        if (res.ok) {
            if (trafficPaused) {
                setTrafficStatus(Color.parseColor("#F59E0B"), getString(R.string.traffic_status_paused, epDisplay));
            } else {
                setTrafficStatus(Color.parseColor("#10B981"), getString(R.string.traffic_status_live, epDisplay));
            }

            metricFlowsVal.setText(String.valueOf(res.totalFlows));
            metricRpsVal.setText(TrafficClient.formatRate(res.reqPerSec));
            metricBytesVal.setText(TrafficClient.formatBytes(res.totalBytes));
            updateTrafficCountBadge(res.bufferedFlows);

            trafficAdapter.setFlows(res.flows);
            if (res.flows.isEmpty()) {
                boolean hasFilter = (selectedChip != CHIP_ALL) || !searchQuery.isEmpty();
                trafficListView.setVisibility(View.GONE);
                trafficEmptyContainer.setVisibility(View.VISIBLE);
                trafficEmptyTitle.setText(hasFilter ? R.string.traffic_empty_filtered_title : R.string.traffic_empty_title);
                trafficEmptyHint.setText(hasFilter
                        ? getString(R.string.traffic_empty_filtered_hint)
                        : getString(R.string.traffic_empty_hint, epDisplay));
                trafficEmptyActionBtn.setVisibility(View.GONE);
            } else {
                trafficEmptyContainer.setVisibility(View.GONE);
                trafficListView.setVisibility(View.VISIBLE);
            }
            return;
        }

        // Error states
        trafficAdapter.setFlows(null);
        trafficListView.setVisibility(View.GONE);
        trafficEmptyContainer.setVisibility(View.VISIBLE);
        updateTrafficCountBadge(0);

        if (res.errorKind == TrafficClient.ErrorKind.NO_PROXY_ENDPOINT) {
            setTrafficStatus(Color.parseColor("#64748B"), getString(R.string.traffic_status_no_endpoint));
            trafficEmptyTitle.setText(R.string.traffic_err_no_endpoint_title);
            trafficEmptyHint.setText(R.string.traffic_err_no_endpoint_hint);
            showEmptyAction(getString(R.string.traffic_btn_open_config), true);
        } else if (res.errorKind == TrafficClient.ErrorKind.UNAUTHORIZED) {
            setTrafficStatus(Color.parseColor("#F59E0B"), getString(R.string.traffic_status_unauth));
            trafficEmptyTitle.setText(R.string.traffic_err_unauth_title);
            trafficEmptyHint.setText(R.string.traffic_err_unauth_hint);
            showEmptyAction(getString(R.string.traffic_btn_open_config), true);
        } else if (res.errorKind == TrafficClient.ErrorKind.OFFLINE) {
            setTrafficStatus(Color.parseColor("#EF4444"), getString(R.string.traffic_status_offline, epDisplay));
            trafficEmptyTitle.setText(R.string.traffic_err_offline_title);
            trafficEmptyHint.setText(getString(R.string.traffic_err_offline_hint, epDisplay));
            showEmptyAction(getString(R.string.traffic_btn_retry), false);
        } else {
            setTrafficStatus(Color.parseColor("#EF4444"), getString(R.string.traffic_status_error));
            trafficEmptyTitle.setText(R.string.traffic_err_api_title);
            trafficEmptyHint.setText(res.errorMessage != null && !res.errorMessage.isEmpty()
                    ? res.errorMessage
                    : getString(R.string.traffic_err_offline_hint, epDisplay));
            showEmptyAction(getString(R.string.traffic_btn_retry), false);
        }
    }

    private void setTrafficStatus(int dotColor, String text) {
        trafficStatusDot.setBackground(roundedRect(dotColor, Color.TRANSPARENT, dp(99), 0));
        trafficStatusText.setText(text);
    }

    private void showEmptyAction(String label, final boolean openConfig) {
        trafficEmptyActionBtn.setText(label);
        trafficEmptyActionBtn.setVisibility(View.VISIBLE);
        trafficEmptyActionBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (openConfig) {
                    openTrafficConfigDialog();
                } else {
                    triggerTrafficPollNow(true);
                }
            }
        });
    }

    private void toggleTrafficPause() {
        trafficPaused = !trafficPaused;
        if (trafficPaused) {
            stopTrafficPolling();
            renderTrafficState();
        } else {
            renderTrafficState();
            if (activeTab == TAB_TRAFFIC && isResumed) {
                triggerTrafficPollNow(false);
            }
        }
    }

    private void onClearTrafficClicked() {
        if (trafficClearBusy) {
            return;
        }
        trafficClearBusy = true;
        trafficClearBtn.setAlpha(0.5f);
        runTrafficIo(new Runnable() {
            @Override
            public void run() {
                Context appCtx = getApplicationContext();
                String endpoint = resolveTrafficEndpoint(appCtx);
                String token = GuardPrefs.getApiToken(appCtx);
                final TrafficClient.ClearResult res = TrafficClient.clearFlows(endpoint, token);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        trafficClearBusy = false;
                        trafficClearBtn.setAlpha(1f);
                        if (res.ok) {
                            Toast.makeText(MainActivity.this, R.string.toast_traffic_cleared, Toast.LENGTH_SHORT).show();
                            trafficAdapter.setFlows(null);
                            updateTrafficCountBadge(0);
                            triggerTrafficPollNow(true);
                        } else {
                            String err = (res.errorMessage != null && !res.errorMessage.isEmpty())
                                    ? res.errorMessage
                                    : String.valueOf(res.errorKind);
                            Toast.makeText(MainActivity.this,
                                    getString(R.string.toast_traffic_clear_failed, err),
                                    Toast.LENGTH_SHORT).show();
                        }
                    }
                });
            }
        });
    }

    // ==================== Traffic Endpoint & Token Settings Dialog ====================

    private void openTrafficConfigDialog() {
        runTrafficIo(new Runnable() {
            @Override
            public void run() {
                Context appCtx = getApplicationContext();
                final String autoEp = resolveAutoTrafficEndpoint(appCtx);
                final String customEp = GuardPrefs.getCustomTrafficEndpoint(appCtx);
                final String currentToken = GuardPrefs.getApiToken(appCtx);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        showTrafficConfigDialogUi(autoEp, customEp, currentToken);
                    }
                });
            }
        });
    }

    private void showTrafficConfigDialogUi(String autoEp, String customEp, String currentToken) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        LinearLayout body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(14), dp(20), dp(8));

        TextView autoInfo = new TextView(this);
        autoInfo.setText(getString(R.string.dialog_traffic_auto_endpoint,
                autoEp.isEmpty() ? getString(R.string.value_none) : autoEp));
        autoInfo.setTextColor(textMuted);
        autoInfo.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        autoInfo.setTypeface(Typeface.MONOSPACE);
        body.addView(autoInfo);

        TextView epLabel = new TextView(this);
        epLabel.setText(R.string.dialog_traffic_endpoint_label);
        epLabel.setTextColor(textPrimary);
        epLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        epLabel.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams epLblLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        epLblLp.topMargin = dp(12);
        body.addView(epLabel, epLblLp);

        final EditText epInput = new EditText(this);
        epInput.setHint(R.string.dialog_traffic_endpoint_hint);
        epInput.setText(customEp);
        epInput.setSingleLine(true);
        epInput.setTypeface(Typeface.MONOSPACE);
        epInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        epInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        body.addView(epInput);

        TextView tokenLabel = new TextView(this);
        tokenLabel.setText(R.string.dialog_traffic_token_label);
        tokenLabel.setTextColor(textPrimary);
        tokenLabel.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        tokenLabel.setTypeface(Typeface.DEFAULT_BOLD);
        LinearLayout.LayoutParams tokLblLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        tokLblLp.topMargin = dp(12);
        body.addView(tokenLabel, tokLblLp);

        final EditText tokenInput = new EditText(this);
        tokenInput.setHint(R.string.dialog_traffic_token_hint);
        tokenInput.setText(currentToken);
        tokenInput.setSingleLine(true);
        tokenInput.setTypeface(Typeface.MONOSPACE);
        tokenInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        tokenInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        body.addView(tokenInput);

        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(R.string.dialog_traffic_config_title)
                .setView(body)
                .setPositiveButton(R.string.dialog_traffic_save, null)
                .setNeutralButton(R.string.dialog_traffic_reset, null)
                .setNegativeButton(R.string.dialog_cancel, null)
                .create();

        showTrackedDialog(dialog);

        Button saveBtn = dialog.getButton(DialogInterface.BUTTON_POSITIVE);
        if (saveBtn != null) {
            saveBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String rawEp = epInput.getText() != null ? epInput.getText().toString().trim() : "";
                    String normalized = "";
                    if (!rawEp.isEmpty()) {
                        normalized = TrafficClient.normalizeEndpoint(rawEp);
                        if (normalized.isEmpty()) {
                            Toast.makeText(MainActivity.this,
                                    R.string.toast_traffic_endpoint_invalid,
                                    Toast.LENGTH_SHORT).show();
                            return;
                        }
                    }
                    String tok = tokenInput.getText() != null ? tokenInput.getText().toString().trim() : "";
                    GuardPrefs.setCustomTrafficEndpoint(MainActivity.this, normalized);
                    GuardPrefs.setApiToken(MainActivity.this, tok);
                    Toast.makeText(MainActivity.this, R.string.toast_traffic_config_saved, Toast.LENGTH_SHORT).show();
                    dialog.dismiss();
                    triggerTrafficPollNow(true);
                }
            });
        }

        Button resetBtn = dialog.getButton(DialogInterface.BUTTON_NEUTRAL);
        if (resetBtn != null) {
            resetBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String tok = tokenInput.getText() != null ? tokenInput.getText().toString().trim() : "";
                    GuardPrefs.setCustomTrafficEndpoint(MainActivity.this, "");
                    GuardPrefs.setApiToken(MainActivity.this, tok);
                    Toast.makeText(MainActivity.this, R.string.toast_traffic_config_saved, Toast.LENGTH_SHORT).show();
                    dialog.dismiss();
                    triggerTrafficPollNow(true);
                }
            });
        }
    }

    // ==================== Rich Flow Detail Dialog ====================

    private void openFlowDetailDialog(final TrafficClient.FlowSummary summary) {
        if (summary == null || isFinishing() || isDestroyed()) {
            return;
        }
        final int gen = detailGen.incrementAndGet();
        final TrafficClient.FlowDetail[] loadedDetail = new TrafficClient.FlowDetail[1];
        final int[] detailActiveTab = new int[]{DETAIL_TAB_OVERVIEW};

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(14), dp(16), dp(8));

        // Summary Title Strip
        LinearLayout topStrip = new LinearLayout(this);
        topStrip.setOrientation(LinearLayout.HORIZONTAL);
        topStrip.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(topStrip);

        TextView methodBadge = new TextView(this);
        methodBadge.setText(summary.method.isEmpty() ? "?" : summary.method);
        methodBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        methodBadge.setTypeface(Typeface.DEFAULT_BOLD);
        methodBadge.setTextColor(Color.parseColor("#38BDF8"));
        methodBadge.setPadding(dp(7), dp(3), dp(7), dp(3));
        methodBadge.setBackground(roundedRect(
                isDarkTheme ? Color.parseColor("#0C2D48") : Color.parseColor("#E0F2FE"),
                Color.TRANSPARENT, dp(5), 0));
        topStrip.addView(methodBadge);

        TextView statusBadge = new TextView(this);
        statusBadge.setText(summary.status > 0 ? String.valueOf(summary.status) : "ERR");
        statusBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        statusBadge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        boolean isErr = summary.status <= 0 || summary.status >= 400 || !summary.error.isEmpty();
        statusBadge.setTextColor(isErr ? Color.parseColor("#FB7185") : Color.parseColor("#34D399"));
        statusBadge.setPadding(dp(7), dp(3), dp(7), dp(3));
        statusBadge.setBackground(roundedRect(
                isErr
                        ? (isDarkTheme ? Color.parseColor("#35121B") : Color.parseColor("#FFE4E6"))
                        : (isDarkTheme ? Color.parseColor("#0A2E24") : Color.parseColor("#D1FAE5")),
                Color.TRANSPARENT, dp(5), 0));
        LinearLayout.LayoutParams sbLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        sbLp.leftMargin = dp(6);
        topStrip.addView(statusBadge, sbLp);

        TextView hostHeader = new TextView(this);
        hostHeader.setText(summary.host.isEmpty() ? TrafficClient.resolveFullUrl(summary) : summary.host);
        hostHeader.setTextColor(textPrimary);
        hostHeader.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        hostHeader.setTypeface(Typeface.DEFAULT_BOLD);
        hostHeader.setSingleLine(true);
        hostHeader.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams hhLp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        hhLp.leftMargin = dp(8);
        topStrip.addView(hostHeader, hhLp);

        // 3-Tab Segmented Switcher (Overview | Request | Response)
        LinearLayout segTrack = new LinearLayout(this);
        segTrack.setOrientation(LinearLayout.HORIZONTAL);
        segTrack.setPadding(dp(3), dp(3), dp(3), dp(3));
        segTrack.setBackground(roundedRect(surfaceColor, borderColor, dp(9), dp(1)));
        LinearLayout.LayoutParams segLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        segLp.topMargin = dp(10);
        root.addView(segTrack, segLp);

        final TextView[] segBtns = new TextView[3];
        int[] segLabels = {
                R.string.detail_tab_overview,
                R.string.detail_tab_request,
                R.string.detail_tab_response
        };

        // Loading / error status banner
        final TextView loadingBanner = new TextView(this);
        loadingBanner.setText(R.string.detail_loading);
        loadingBanner.setTextColor(Color.parseColor("#38BDF8"));
        loadingBanner.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        loadingBanner.setPadding(0, dp(8), 0, dp(4));
        root.addView(loadingBanner);

        // Scrollable body pane
        DisplayMetrics dm = getResources().getDisplayMetrics();
        int maxScrollHeight = Math.min(dp(420), (int) (dm.heightPixels * 0.50f));
        ScrollView scroll = new ScrollView(this);
        LinearLayout.LayoutParams scrollLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, maxScrollHeight);
        scrollLp.topMargin = dp(6);
        root.addView(scroll, scrollLp);

        FrameLayout panes = new FrameLayout(this);
        scroll.addView(panes);

        // Pane 0: Overview (immediately populated from summary)
        final LinearLayout overviewPane = buildOverviewPane(summary);
        panes.addView(overviewPane);

        // Pane 1: Request (populated once detail arrives)
        final LinearLayout reqPane = new LinearLayout(this);
        reqPane.setOrientation(LinearLayout.VERTICAL);
        reqPane.setVisibility(View.GONE);
        panes.addView(reqPane);

        // Pane 2: Response (populated once detail arrives)
        final LinearLayout respPane = new LinearLayout(this);
        respPane.setOrientation(LinearLayout.VERTICAL);
        respPane.setVisibility(View.GONE);
        panes.addView(respPane);

        final Runnable updateDetailTabs = new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < segBtns.length; i++) {
                    boolean active = (i == detailActiveTab[0]);
                    segBtns[i].setTextColor(active ? Color.WHITE : textMuted);
                    segBtns[i].setBackground(active
                            ? roundedRect(accentColor, Color.TRANSPARENT, dp(7), 0)
                            : null);
                }
                overviewPane.setVisibility(detailActiveTab[0] == DETAIL_TAB_OVERVIEW ? View.VISIBLE : View.GONE);
                reqPane.setVisibility(detailActiveTab[0] == DETAIL_TAB_REQUEST ? View.VISIBLE : View.GONE);
                respPane.setVisibility(detailActiveTab[0] == DETAIL_TAB_RESPONSE ? View.VISIBLE : View.GONE);
            }
        };

        for (int i = 0; i < 3; i++) {
            final int idx = i;
            TextView seg = new TextView(this);
            seg.setText(segLabels[i]);
            seg.setGravity(Gravity.CENTER);
            seg.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
            seg.setTypeface(Typeface.DEFAULT_BOLD);
            seg.setPadding(dp(8), dp(7), dp(8), dp(7));
            seg.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    detailActiveTab[0] = idx;
                    updateDetailTabs.run();
                }
            });
            segTrack.addView(seg, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            segBtns[i] = seg;
        }
        updateDetailTabs.run();

        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(root)
                .setPositiveButton(R.string.detail_btn_copy_url, null)
                .setNeutralButton(R.string.detail_btn_copy_curl, null)
                .setNegativeButton(R.string.dialog_close, null)
                .create();

        showTrackedDialog(dialog);

        Button copyUrlBtn = dialog.getButton(DialogInterface.BUTTON_POSITIVE);
        if (copyUrlBtn != null) {
            copyUrlBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    String fullUrl = TrafficClient.resolveFullUrl(
                            loadedDetail[0] != null ? loadedDetail[0] : summary);
                    copyToClipboard("Flow URL", fullUrl);
                }
            });
        }

        Button copyCurlBtn = dialog.getButton(DialogInterface.BUTTON_NEUTRAL);
        if (copyCurlBtn != null) {
            copyCurlBtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    TrafficClient.FlowDetail d = loadedDetail[0];
                    if (d == null) {
                        d = new TrafficClient.FlowDetail();
                        d.method = summary.method;
                        d.scheme = summary.scheme;
                        d.host = summary.host;
                        d.path = summary.path;
                        d.url = summary.url;
                    }
                    String curl = TrafficClient.buildCurlCommand(d);
                    copyToClipboard("cURL Command", curl);
                }
            });
        }

        // Fetch full headers + bodies off main thread
        runTrafficIo(new Runnable() {
            @Override
            public void run() {
                Context appCtx = getApplicationContext();
                String endpoint = resolveTrafficEndpoint(appCtx);
                String token = GuardPrefs.getApiToken(appCtx);
                final TrafficClient.FlowDetailResult res = TrafficClient.fetchFlowDetail(endpoint, token, summary.id);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed() || detailGen.get() != gen || !dialog.isShowing()) {
                            return;
                        }
                        if (!res.ok || res.flow == null) {
                            String err = (res.errorMessage != null && !res.errorMessage.isEmpty())
                                    ? res.errorMessage
                                    : String.valueOf(res.errorKind);
                            loadingBanner.setText(getString(R.string.detail_load_failed, err));
                            loadingBanner.setTextColor(Color.parseColor("#FB7185"));
                            return;
                        }
                        loadingBanner.setVisibility(View.GONE);
                        loadedDetail[0] = res.flow;

                        String reqCt = TrafficClient.findHeaderIgnoreCase(res.flow.reqHeaders, "Content-Type");
                        populateMessagePane(
                                reqPane,
                                R.string.detail_section_req_headers,
                                res.flow.reqHeaders,
                                R.string.detail_section_req_body,
                                res.flow.reqBody,
                                reqCt,
                                res.flow.reqBodyTruncated,
                                res.flow.reqBodyBinary);

                        String respCt = !res.flow.contentType.isEmpty()
                                ? res.flow.contentType
                                : TrafficClient.findHeaderIgnoreCase(res.flow.respHeaders, "Content-Type");
                        populateMessagePane(
                                respPane,
                                R.string.detail_section_resp_headers,
                                res.flow.respHeaders,
                                R.string.detail_section_resp_body,
                                res.flow.respBody,
                                respCt,
                                res.flow.respBodyTruncated,
                                res.flow.respBodyBinary);
                    }
                });
            }
        });
    }

    private LinearLayout buildOverviewPane(TrafficClient.FlowSummary s) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);

        addDetailField(box, R.string.detail_field_url, TrafficClient.resolveFullUrl(s), true);
        addDetailField(box, R.string.detail_field_method, s.method, true);
        addDetailField(box, R.string.detail_field_status, s.status > 0 ? String.valueOf(s.status) : "ERR", true);
        addDetailField(box, R.string.detail_field_scheme, s.scheme.toUpperCase(Locale.US), false);
        addDetailField(box, R.string.detail_field_host, s.host, true);
        addDetailField(box, R.string.detail_field_path, s.path.isEmpty() ? "/" : s.path, true);
        if (!s.contentType.isEmpty()) {
            addDetailField(box, R.string.detail_field_content_type, s.contentType, true);
        }
        addDetailField(box, R.string.detail_field_latency, TrafficClient.formatLatency(s.latencyMs), true);
        addDetailField(box, R.string.detail_field_req_size, TrafficClient.formatBytes(s.reqBytes), true);
        addDetailField(box, R.string.detail_field_resp_size, TrafficClient.formatBytes(s.respBytes), true);
        if (s.timestampMs > 0) {
            addDetailField(box, R.string.detail_field_time, TrafficClient.formatTimestamp(s.timestampMs), true);
        }
        if (s.error != null && !s.error.isEmpty()) {
            addDetailField(box, R.string.detail_field_error, s.error, true);
        }
        return box;
    }

    private void addDetailField(LinearLayout parent, int labelRes, String value, boolean mono) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(4), 0, dp(6));

        TextView lbl = new TextView(this);
        lbl.setText(labelRes);
        lbl.setTextColor(textMuted);
        lbl.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        lbl.setTypeface(Typeface.DEFAULT_BOLD);
        row.addView(lbl);

        TextView val = new TextView(this);
        val.setText(value != null && !value.isEmpty() ? value : "-");
        val.setTextColor(textPrimary);
        val.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        val.setTextIsSelectable(true);
        if (mono) {
            val.setTypeface(Typeface.MONOSPACE);
        }
        LinearLayout.LayoutParams vLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        vLp.topMargin = dp(2);
        row.addView(val, vLp);

        parent.addView(row);
    }

    private void populateMessagePane(
            LinearLayout pane,
            int headersTitleRes,
            Map<String, String> headers,
            int bodyTitleRes,
            String rawBody,
            String contentType,
            boolean truncated,
            boolean binary) {
        pane.removeAllViews();

        // Headers header
        TextView hTitle = new TextView(this);
        hTitle.setText(headersTitleRes);
        hTitle.setTextColor(textMuted);
        hTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        hTitle.setTypeface(Typeface.DEFAULT_BOLD);
        pane.addView(hTitle);

        StringBuilder headersText = new StringBuilder();
        if (headers != null && !headers.isEmpty()) {
            boolean first = true;
            for (Map.Entry<String, String> e : headers.entrySet()) {
                if (!first) {
                    headersText.append('\n');
                }
                first = false;
                headersText.append(e.getKey()).append(": ").append(e.getValue());
            }
        }
        TextView headersBox = createMonospaceCodeBox(
                headersText.length() > 0 ? headersText.toString() : getString(R.string.detail_empty_headers),
                headersText.length() > 0);
        LinearLayout.LayoutParams hbLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        hbLp.topMargin = dp(4);
        pane.addView(headersBox, hbLp);

        // Body section title + badges
        LinearLayout bTitleRow = new LinearLayout(this);
        bTitleRow.setOrientation(LinearLayout.HORIZONTAL);
        bTitleRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams btrLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        btrLp.topMargin = dp(12);
        pane.addView(bTitleRow, btrLp);

        TextView bTitle = new TextView(this);
        bTitle.setText(bodyTitleRes);
        bTitle.setTextColor(textMuted);
        bTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        bTitle.setTypeface(Typeface.DEFAULT_BOLD);
        bTitleRow.addView(bTitle);

        if (binary) {
            addInlineBadge(bTitleRow, R.string.detail_badge_binary,
                    Color.parseColor("#A78BFA"),
                    isDarkTheme ? Color.parseColor("#24193B") : Color.parseColor("#EDE9FE"));
        }
        if (truncated) {
            addInlineBadge(bTitleRow, R.string.detail_badge_truncated,
                    Color.parseColor("#FBBF24"),
                    isDarkTheme ? Color.parseColor("#33240B") : Color.parseColor("#FEF3C7"));
        }

        String displayBody;
        if (rawBody == null || rawBody.isEmpty()) {
            displayBody = getString(R.string.detail_empty_body);
        } else if (binary) {
            displayBody = rawBody;
        } else {
            displayBody = TrafficClient.prettyPrintBody(rawBody, contentType);
        }
        boolean hasBody = rawBody != null && !rawBody.isEmpty();
        TextView bodyBox = createMonospaceCodeBox(displayBody, hasBody);
        LinearLayout.LayoutParams bbLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        bbLp.topMargin = dp(4);
        pane.addView(bodyBox, bbLp);
    }

    private void addInlineBadge(LinearLayout parent, int textRes, int fg, int bg) {
        TextView badge = new TextView(this);
        badge.setText(textRes);
        badge.setTextColor(fg);
        badge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
        badge.setTypeface(Typeface.DEFAULT_BOLD);
        badge.setPadding(dp(6), dp(2), dp(6), dp(2));
        badge.setBackground(roundedRect(bg, Color.TRANSPARENT, dp(4), 0));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.leftMargin = dp(6);
        parent.addView(badge, lp);
    }

    private TextView createMonospaceCodeBox(String content, boolean primaryColor) {
        TextView tv = new TextView(this);
        tv.setText(content);
        tv.setTextColor(primaryColor ? textPrimary : textMuted);
        tv.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        tv.setTypeface(Typeface.MONOSPACE);
        tv.setTextIsSelectable(true);
        tv.setLineSpacing(dp(2), 1f);
        tv.setPadding(dp(10), dp(8), dp(10), dp(8));
        tv.setBackground(roundedRect(surfaceColor, borderColor, dp(8), dp(1)));
        return tv;
    }

    private void showTrackedDialog(AlertDialog dialog) {
        if (dialog == null || isFinishing() || isDestroyed()) {
            return;
        }
        dismissActiveDialog();
        activeDialog = dialog;
        dialog.show();
    }

    private void dismissActiveDialog() {
        if (activeDialog != null) {
            try {
                if (activeDialog.isShowing()) {
                    activeDialog.dismiss();
                }
            } catch (Throwable ignored) {
            }
            activeDialog = null;
        }
    }

    // ==================== Shared UI Helpers ====================

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
        return "1.3.1";
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

    private void runTrafficIo(Runnable task) {
        if (isFinishing() || isDestroyed() || trafficExecutor.isShutdown()) {
            return;
        }
        try {
            trafficExecutor.execute(task);
        } catch (RejectedExecutionException ignored) {
        }
    }

    // ==================== Async Guard Inspection & Rendering ====================

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
                String errMsg = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
                Toast.makeText(
                        this,
                        getString(R.string.toast_clean_failed_detail, errMsg),
                        Toast.LENGTH_LONG).show();
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
                final ProxyCleaner.CleanupResult res = ProxyCleaner.cleanupDetailed(
                        MainActivity.this, modeToClean, redirPort);
                GuardPrefs.recordCleanup(MainActivity.this, getString(R.string.reason_manual), res.ok);
                final String message = res.formatFailureMessage(MainActivity.this);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        localCleanupBusy = false;
                        Toast.makeText(
                                MainActivity.this,
                                message,
                                res.ok ? Toast.LENGTH_SHORT : Toast.LENGTH_LONG).show();
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
            showTrackedDialog(builder.create());
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
            showTrackedDialog(builder.create());
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
            showTrackedDialog(builder.create());
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
                cm.setPrimaryClip(ClipData.newPlainText(label, text != null ? text : ""));
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
        final String apiToken = intent.getStringExtra(EXTRA_API_TOKEN);
        final String certHash = CertInspector.normalizeHash(intent.getStringExtra(EXTRA_CERT_HASH));
        final String certFp = intent.getStringExtra(EXTRA_CERT_FP);
        final String certB64 = intent.getStringExtra(EXTRA_CERT_B64);
        final boolean autoInstall = intent.getBooleanExtra(EXTRA_INSTALL_CERT, false);
        if (autoInstall) {
            intent.removeExtra(EXTRA_INSTALL_CERT);
        }

        boolean hasToken = apiToken != null && !apiToken.trim().isEmpty();
        if (!hasToken && certHash.isEmpty() && (certFp == null || certFp.trim().isEmpty()) && certB64 == null && !autoInstall) {
            return;
        }

        final String pathSnapshot = pendingCertPath;
        runIo(new Runnable() {
            @Override
            public void run() {
                if (apiToken != null && !apiToken.trim().isEmpty()) {
                    GuardPrefs.saveApiToken(MainActivity.this, apiToken);
                }
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
