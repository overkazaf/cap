package com.overkazaf.cap.companion;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyChain;
import android.util.Base64;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Minimalist dark/light aware status screen for Cap Guard.
 * Displays live proxy watchdog status, global proxy state, CA cert availability,
 * one-tap "Disconnect & Clean Proxy", and one-tap KeyChain CA certificate installer.
 */
public class MainActivity extends Activity {
    public static final String EXTRA_INSTALL_CERT = "install_cert";
    public static final String EXTRA_CERT_PATH = "cert_path";
    public static final String EXTRA_CERT_B64 = "cert_b64";
    private static final int REQ_INSTALL_CERT = 2001;

    private TextView statusBadgeView;
    private TextView activeProxyValue;
    private TextView globalProxyValue;
    private TextView modeValue;
    private TextView permissionValue;
    private TextView watchdogValue;
    private TextView certValue;
    private TextView lastCleanupValue;

    private boolean isDarkTheme;
    private String pendingCertPath;

    private final BroadcastReceiver statusReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            refreshStatus();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int nightMode = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;
        isDarkTheme = (nightMode == Configuration.UI_MODE_NIGHT_YES);

        applySystemBarColors();
        setContentView(buildContentView());
        refreshStatus();
        handleIntentExtras(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        refreshStatus();
        handleIntentExtras(intent);
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
        refreshStatus();
    }

    @Override
    protected void onPause() {
        try {
            unregisterReceiver(statusReceiver);
        } catch (Throwable ignored) {
        }
        super.onPause();
    }

    private void applySystemBarColors() {
        Window window = getWindow();
        if (window != null) {
            int bg = isDarkTheme ? Color.parseColor("#0B0F17") : Color.parseColor("#F4F6FA");
            window.setStatusBarColor(bg);
            window.setNavigationBarColor(bg);
            if (!isDarkTheme && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                View decor = window.getDecorView();
                decor.setSystemUiVisibility(decor.getSystemUiVisibility() | View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
            }
        }
    }

    private View buildContentView() {
        int bgColor = isDarkTheme ? Color.parseColor("#0B0F17") : Color.parseColor("#F4F6FA");
        int cardColor = isDarkTheme ? Color.parseColor("#131A27") : Color.parseColor("#FFFFFF");
        int borderColor = isDarkTheme ? Color.parseColor("#243045") : Color.parseColor("#E2E8F0");
        int textPrimary = isDarkTheme ? Color.parseColor("#F1F5F9") : Color.parseColor("#0F172A");
        int textMuted = isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#64748B");

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(bgColor);
        scroll.setFillViewport(true);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(20), dp(24), dp(20), dp(28));
        scroll.addView(root);

        // Header row
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        root.addView(header);

        ImageView icon = new ImageView(this);
        icon.setImageResource(R.drawable.ic_launcher);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(dp(44), dp(44));
        iconLp.rightMargin = dp(14);
        header.addView(icon, iconLp);

        LinearLayout titleCol = new LinearLayout(this);
        titleCol.setOrientation(LinearLayout.VERTICAL);
        LinearLayout.LayoutParams titleColLp = new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        header.addView(titleCol, titleColLp);

        TextView title = new TextView(this);
        title.setText(R.string.app_name);
        title.setTextColor(textPrimary);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        titleCol.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText(R.string.app_subtitle);
        subtitle.setTextColor(textMuted);
        subtitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        titleCol.addView(subtitle);

        statusBadgeView = new TextView(this);
        statusBadgeView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        statusBadgeView.setTypeface(Typeface.DEFAULT_BOLD);
        statusBadgeView.setPadding(dp(10), dp(5), dp(10), dp(5));
        header.addView(statusBadgeView);

        // Status Card
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(16), dp(14), dp(16), dp(14));
        card.setBackground(roundedRect(cardColor, borderColor, dp(12), dp(1)));
        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        cardLp.topMargin = dp(20);
        root.addView(card, cardLp);

        activeProxyValue = addRow(card, R.string.label_proxy_target, textMuted, textPrimary, true);
        globalProxyValue = addRow(card, R.string.label_global_proxy, textMuted, textPrimary, true);
        modeValue = addRow(card, R.string.label_mode, textMuted, textPrimary, false);
        watchdogValue = addRow(card, R.string.label_watchdog, textMuted, textPrimary, false);
        permissionValue = addRow(card, R.string.label_permission, textMuted, textPrimary, false);
        certValue = addRow(card, R.string.label_cert, textMuted, textPrimary, false);
        lastCleanupValue = addRow(card, R.string.label_last_cleanup, textMuted, textPrimary, false);

        // Primary action: Disconnect & Clean Proxy
        Button restoreBtn = createActionButton(
                getString(R.string.btn_restore_network),
                Color.parseColor("#EF4444"),
                Color.WHITE,
                Color.TRANSPARENT);
        restoreBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                onRestoreClicked();
            }
        });
        LinearLayout.LayoutParams btnLp1 = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        btnLp1.topMargin = dp(20);
        root.addView(restoreBtn, btnLp1);

        // Secondary action: Install CA Certificate
        Button certBtn = createActionButton(
                getString(R.string.btn_install_cert),
                Color.parseColor("#3B82F6"),
                Color.WHITE,
                Color.TRANSPARENT);
        certBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                launchCertInstall(pendingCertPath);
            }
        });
        LinearLayout.LayoutParams btnLp2 = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        btnLp2.topMargin = dp(10);
        root.addView(certBtn, btnLp2);

        // Tertiary action: Refresh Status
        Button refreshBtn = createActionButton(
                getString(R.string.btn_refresh),
                cardColor,
                textPrimary,
                borderColor);
        refreshBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                refreshStatus();
            }
        });
        LinearLayout.LayoutParams btnLp3 = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        btnLp3.topMargin = dp(10);
        root.addView(refreshBtn, btnLp3);

        // Footer hint
        TextView footer = new TextView(this);
        footer.setText(R.string.footer_hint);
        footer.setTextColor(textMuted);
        footer.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        footer.setLineSpacing(dp(3), 1f);
        LinearLayout.LayoutParams footerLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        footerLp.topMargin = dp(18);
        root.addView(footer, footerLp);

        return scroll;
    }

    private TextView addRow(LinearLayout parent, int labelRes, int labelColor, int valueColor, boolean mono) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));

        TextView label = new TextView(this);
        label.setText(labelRes);
        label.setTextColor(labelColor);
        label.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        row.addView(label);

        TextView value = new TextView(this);
        value.setTextColor(valueColor);
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

    private Button createActionButton(String text, int bgColor, int textColor, int strokeColor) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setAllCaps(false);
        btn.setTextColor(textColor);
        btn.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        btn.setTypeface(Typeface.DEFAULT_BOLD);
        btn.setPadding(dp(16), dp(14), dp(16), dp(14));
        btn.setBackground(roundedRect(bgColor, strokeColor, dp(10), strokeColor == Color.TRANSPARENT ? 0 : dp(1)));
        return btn;
    }

    private void refreshStatus() {
        boolean guardActive = ProxyGuardService.isServiceRunning() || GuardPrefs.isActive(this);
        String globalProxy = ProxyCleaner.getGlobalHttpProxy(this);
        boolean hasPerm = ProxyCleaner.hasWriteSecureSettings(this);

        if (guardActive) {
            statusBadgeView.setText(R.string.status_protected);
            statusBadgeView.setTextColor(Color.parseColor("#10B981"));
            statusBadgeView.setBackground(roundedRect(
                    isDarkTheme ? Color.parseColor("#0D2F24") : Color.parseColor("#D1FAE5"),
                    Color.parseColor("#10B981"), dp(99), dp(1)));
        } else if (!globalProxy.isEmpty()) {
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

        String host = GuardPrefs.getProxyHost(this);
        int port = GuardPrefs.getProxyPort(this);
        if (guardActive && !host.isEmpty()) {
            activeProxyValue.setText(host + ":" + port);
        } else {
            activeProxyValue.setText(R.string.value_none);
        }

        globalProxyValue.setText(globalProxy.isEmpty() ? getString(R.string.value_none) : globalProxy);

        String mode = GuardPrefs.getMode(this);
        if (guardActive) {
            modeValue.setText("vpn".equalsIgnoreCase(mode) ? R.string.mode_vpn : R.string.mode_proxy);
        } else {
            modeValue.setText(R.string.value_none);
        }

        if (ProxyGuardService.isServiceRunning()) {
            watchdogValue.setText(getString(
                    R.string.value_watchdog_running,
                    GuardPrefs.getMissCount(this),
                    GuardPrefs.getMissThreshold(this)));
        } else {
            watchdogValue.setText(R.string.value_watchdog_stopped);
        }

        permissionValue.setText(hasPerm ? R.string.value_granted : R.string.value_missing_perm);
        permissionValue.setTextColor(hasPerm
                ? Color.parseColor("#10B981")
                : Color.parseColor("#F59E0B"));

        File certFile = ProxyCleaner.findCertFile(this, pendingCertPath);
        certValue.setText(certFile != null ? R.string.value_cert_ready : R.string.value_cert_missing);

        long lastTs = GuardPrefs.getLastCleanupTs(this);
        if (lastTs > 0) {
            String timeStr = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date(lastTs));
            String reason = GuardPrefs.getLastCleanupReason(this);
            lastCleanupValue.setText(timeStr + " · " + reason);
        } else {
            lastCleanupValue.setText(R.string.value_none);
        }
    }

    private void onRestoreClicked() {
        if (ProxyGuardService.isServiceRunning()) {
            Intent stopIntent = new Intent(this, ProxyGuardService.class);
            stopIntent.setAction(ProxyGuardService.ACTION_RESTORE);
            startService(stopIntent);
            Toast.makeText(this, R.string.toast_cleaned, Toast.LENGTH_SHORT).show();
            return;
        }
        new Thread(new Runnable() {
            @Override
            public void run() {
                final boolean ok = ProxyCleaner.cleanup(
                        MainActivity.this,
                        GuardPrefs.getMode(MainActivity.this),
                        GuardPrefs.getRedirPort(MainActivity.this));
                GuardPrefs.recordCleanup(MainActivity.this, getString(R.string.reason_manual), ok);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(
                                MainActivity.this,
                                ok ? R.string.toast_cleaned : R.string.toast_clean_failed,
                                Toast.LENGTH_SHORT).show();
                        refreshStatus();
                    }
                });
            }
        }, "cap-guard-manual-clean").start();
    }

    private void handleIntentExtras(Intent intent) {
        if (intent == null) {
            return;
        }
        if (intent.hasExtra(EXTRA_CERT_PATH)) {
            pendingCertPath = intent.getStringExtra(EXTRA_CERT_PATH);
        }
        String certB64 = intent.getStringExtra(EXTRA_CERT_B64);
        if (intent.getBooleanExtra(EXTRA_INSTALL_CERT, false)) {
            intent.removeExtra(EXTRA_INSTALL_CERT);
            if (certB64 != null && !certB64.trim().isEmpty()) {
                launchCertInstallBytes(Base64.decode(certB64.trim(), Base64.DEFAULT));
            } else {
                launchCertInstall(pendingCertPath);
            }
        }
    }

    private void launchCertInstall(String preferredPath) {
        File certFile = ProxyCleaner.findCertFile(this, preferredPath);
        if (certFile == null) {
            Toast.makeText(this, R.string.toast_cert_not_found, Toast.LENGTH_LONG).show();
            return;
        }
        try {
            launchCertInstallBytes(readAllBytes(certFile));
        } catch (Throwable t) {
            Toast.makeText(this, getString(R.string.toast_cert_failed, t.getMessage()), Toast.LENGTH_LONG).show();
        }
    }

    private void launchCertInstallBytes(byte[] certBytes) {
        try {
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, certBytes);
            installIntent.putExtra(KeyChain.EXTRA_NAME, "Cap MITM CA");
            startActivityForResult(installIntent, REQ_INSTALL_CERT);
            Toast.makeText(this, R.string.toast_cert_launched, Toast.LENGTH_SHORT).show();
        } catch (Throwable t) {
            Toast.makeText(this, getString(R.string.toast_cert_failed, t.getMessage()), Toast.LENGTH_LONG).show();
        }
    }

    private static byte[] readAllBytes(File file) throws Exception {
        InputStream in = new FileInputStream(file);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) >= 0) {
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
