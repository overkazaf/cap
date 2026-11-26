package com.overkazaf.cap.companion;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * ViewHolder-backed {@link BaseAdapter} for smooth 60fps scrolling of live
 * proxy flows in Cap's dark/light card palette.
 */
public final class TrafficAdapter extends BaseAdapter {
    private final Context context;
    private final boolean isDarkTheme;
    private final List<TrafficClient.FlowSummary> items = new ArrayList<TrafficClient.FlowSummary>();

    private final int cardBg;
    private final int cardBorder;
    private final int hostColor;
    private final int pathColor;
    private final int metaColor;
    private final int errorTextColor;

    public TrafficAdapter(Context context, boolean isDarkTheme) {
        this.context = context;
        this.isDarkTheme = isDarkTheme;
        this.cardBg = isDarkTheme ? Color.parseColor("#0F172A") : Color.parseColor("#FFFFFF");
        this.cardBorder = isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#E2E8F0");
        this.hostColor = isDarkTheme ? Color.parseColor("#F1F5F9") : Color.parseColor("#0F172A");
        this.pathColor = isDarkTheme ? Color.parseColor("#CBD5E1") : Color.parseColor("#334155");
        this.metaColor = isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#64748B");
        this.errorTextColor = isDarkTheme ? Color.parseColor("#FB7185") : Color.parseColor("#E11D48");
    }

    public void setFlows(List<TrafficClient.FlowSummary> flows) {
        items.clear();
        if (flows != null && !flows.isEmpty()) {
            items.addAll(flows);
        }
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return items.size();
    }

    @Override
    public TrafficClient.FlowSummary getItem(int position) {
        if (position < 0 || position >= items.size()) {
            return null;
        }
        return items.get(position);
    }

    @Override
    public long getItemId(int position) {
        TrafficClient.FlowSummary item = getItem(position);
        return item != null ? item.seq : position;
    }

    @Override
    public boolean hasStableIds() {
        return true;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder vh;
        if (convertView == null) {
            vh = createHolder();
            convertView = vh.root;
            convertView.setTag(vh);
        } else {
            vh = (ViewHolder) convertView.getTag();
        }

        TrafficClient.FlowSummary flow = getItem(position);
        if (flow != null) {
            bindHolder(vh, flow);
        }
        return convertView;
    }

    private ViewHolder createHolder() {
        ViewHolder vh = new ViewHolder();

        LinearLayout wrapper = new LinearLayout(context);
        wrapper.setOrientation(LinearLayout.VERTICAL);
        wrapper.setPadding(0, 0, 0, dp(8));

        LinearLayout card = new LinearLayout(context);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setPadding(dp(12), dp(10), dp(12), dp(10));
        card.setBackground(makeRounded(cardBg, cardBorder, dp(10), dp(1)));
        wrapper.addView(card, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        // Top row: [METHOD] [Host ..........................] [STATUS]
        LinearLayout topRow = new LinearLayout(context);
        topRow.setOrientation(LinearLayout.HORIZONTAL);
        topRow.setGravity(Gravity.CENTER_VERTICAL);
        card.addView(topRow, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        vh.methodBg = makeRounded(Color.TRANSPARENT, Color.TRANSPARENT, dp(5), 0);
        vh.methodPill = new TextView(context);
        vh.methodPill.setTextSize(TypedValue.COMPLEX_UNIT_SP, 10);
        vh.methodPill.setTypeface(Typeface.DEFAULT_BOLD);
        vh.methodPill.setGravity(Gravity.CENTER);
        vh.methodPill.setMinWidth(dp(44));
        vh.methodPill.setPadding(dp(6), dp(2), dp(6), dp(2));
        vh.methodPill.setBackground(vh.methodBg);
        topRow.addView(vh.methodPill, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        vh.hostText = new TextView(context);
        vh.hostText.setTextColor(hostColor);
        vh.hostText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        vh.hostText.setTypeface(Typeface.DEFAULT_BOLD);
        vh.hostText.setSingleLine(true);
        vh.hostText.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams hostLp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        hostLp.leftMargin = dp(8);
        hostLp.rightMargin = dp(8);
        topRow.addView(vh.hostText, hostLp);

        vh.statusBg = makeRounded(Color.TRANSPARENT, Color.TRANSPARENT, dp(5), 0);
        vh.statusBadge = new TextView(context);
        vh.statusBadge.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        vh.statusBadge.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        vh.statusBadge.setGravity(Gravity.CENTER);
        vh.statusBadge.setMinWidth(dp(36));
        vh.statusBadge.setPadding(dp(6), dp(2), dp(6), dp(2));
        vh.statusBadge.setBackground(vh.statusBg);
        topRow.addView(vh.statusBadge, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        // Middle row: Path
        vh.pathText = new TextView(context);
        vh.pathText.setTextColor(pathColor);
        vh.pathText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        vh.pathText.setTypeface(Typeface.MONOSPACE);
        vh.pathText.setSingleLine(true);
        vh.pathText.setEllipsize(TextUtils.TruncateAt.END);
        LinearLayout.LayoutParams pathLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        pathLp.topMargin = dp(5);
        card.addView(vh.pathText, pathLp);

        // Bottom meta row: [HTTPS]  124 ms  4.2 KB        12:34:56
        LinearLayout metaRow = new LinearLayout(context);
        metaRow.setOrientation(LinearLayout.HORIZONTAL);
        metaRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams metaRowLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        metaRowLp.topMargin = dp(6);
        card.addView(metaRow, metaRowLp);

        vh.schemeBg = makeRounded(Color.TRANSPARENT, Color.TRANSPARENT, dp(4), 0);
        vh.schemeTag = new TextView(context);
        vh.schemeTag.setTextSize(TypedValue.COMPLEX_UNIT_SP, 9);
        vh.schemeTag.setTypeface(Typeface.DEFAULT_BOLD);
        vh.schemeTag.setPadding(dp(5), dp(1), dp(5), dp(1));
        vh.schemeTag.setBackground(vh.schemeBg);
        metaRow.addView(vh.schemeTag, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        vh.latencyText = new TextView(context);
        vh.latencyText.setTextColor(metaColor);
        vh.latencyText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        vh.latencyText.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams latLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        latLp.leftMargin = dp(8);
        metaRow.addView(vh.latencyText, latLp);

        vh.sizeText = new TextView(context);
        vh.sizeText.setTextColor(metaColor);
        vh.sizeText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        vh.sizeText.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams sizeLp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        sizeLp.leftMargin = dp(8);
        metaRow.addView(vh.sizeText, sizeLp);

        vh.timeText = new TextView(context);
        vh.timeText.setTextColor(metaColor);
        vh.timeText.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        vh.timeText.setTypeface(Typeface.MONOSPACE);
        metaRow.addView(vh.timeText, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT));

        vh.root = wrapper;
        return vh;
    }

    private void bindHolder(ViewHolder vh, TrafficClient.FlowSummary flow) {
        // Method pill
        String method = (flow.method == null || flow.method.isEmpty()) ? "?" : flow.method;
        vh.methodPill.setText(method);
        styleMethodPill(vh.methodPill, vh.methodBg, method);

        // Host
        String host = (flow.host == null || flow.host.isEmpty())
                ? TrafficClient.resolveFullUrl(flow)
                : flow.host;
        vh.hostText.setText(host);

        // Status badge
        boolean hasError = flow.error != null && !flow.error.isEmpty();
        if (flow.status > 0) {
            vh.statusBadge.setText(String.valueOf(flow.status));
        } else {
            vh.statusBadge.setText("ERR");
        }
        styleStatusBadge(vh.statusBadge, vh.statusBg, flow.status, hasError);

        // Path (or error note)
        String path = (flow.path == null || flow.path.isEmpty()) ? "/" : flow.path;
        if (hasError) {
            vh.pathText.setText(path + " · " + flow.error);
            vh.pathText.setTextColor(errorTextColor);
        } else {
            vh.pathText.setText(path);
            vh.pathText.setTextColor(pathColor);
        }

        // Scheme tag
        String scheme = (flow.scheme == null || flow.scheme.isEmpty())
                ? "HTTP"
                : flow.scheme.toUpperCase(Locale.US);
        vh.schemeTag.setText(scheme);
        if ("HTTPS".equals(scheme)) {
            vh.schemeTag.setTextColor(isDarkTheme ? Color.parseColor("#34D399") : Color.parseColor("#047857"));
            vh.schemeBg.setColor(isDarkTheme ? Color.parseColor("#0A2E24") : Color.parseColor("#D1FAE5"));
        } else {
            vh.schemeTag.setTextColor(isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
            vh.schemeBg.setColor(isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#E2E8F0"));
        }

        vh.latencyText.setText(TrafficClient.formatLatency(flow.latencyMs));
        vh.sizeText.setText(TrafficClient.formatBytes(flow.respBytes));
        vh.timeText.setText(TrafficClient.formatTimestamp(flow.timestampMs));
    }

    private void styleMethodPill(TextView tv, GradientDrawable bg, String method) {
        if ("GET".equals(method)) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#38BDF8") : Color.parseColor("#0284C7"));
            bg.setColor(isDarkTheme ? Color.parseColor("#0C2D48") : Color.parseColor("#E0F2FE"));
        } else if ("POST".equals(method)) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#34D399") : Color.parseColor("#059669"));
            bg.setColor(isDarkTheme ? Color.parseColor("#0A2E24") : Color.parseColor("#D1FAE5"));
        } else if ("PUT".equals(method) || "PATCH".equals(method)) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#FBBF24") : Color.parseColor("#D97706"));
            bg.setColor(isDarkTheme ? Color.parseColor("#33240B") : Color.parseColor("#FEF3C7"));
        } else if ("DELETE".equals(method)) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#FB7185") : Color.parseColor("#E11D48"));
            bg.setColor(isDarkTheme ? Color.parseColor("#35121B") : Color.parseColor("#FFE4E6"));
        } else {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
            bg.setColor(isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#E2E8F0"));
        }
    }

    private void styleStatusBadge(TextView tv, GradientDrawable bg, int status, boolean hasError) {
        if (hasError || status <= 0 || status >= 500) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#FB7185") : Color.parseColor("#E11D48"));
            bg.setColor(isDarkTheme ? Color.parseColor("#35121B") : Color.parseColor("#FFE4E6"));
        } else if (status >= 200 && status < 300) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#34D399") : Color.parseColor("#059669"));
            bg.setColor(isDarkTheme ? Color.parseColor("#0A2E24") : Color.parseColor("#D1FAE5"));
        } else if (status >= 300 && status < 400) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#22D3EE") : Color.parseColor("#0891B2"));
            bg.setColor(isDarkTheme ? Color.parseColor("#0A2A35") : Color.parseColor("#CFFAFE"));
        } else if (status >= 400) {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#FBBF24") : Color.parseColor("#D97706"));
            bg.setColor(isDarkTheme ? Color.parseColor("#33240B") : Color.parseColor("#FEF3C7"));
        } else {
            tv.setTextColor(isDarkTheme ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
            bg.setColor(isDarkTheme ? Color.parseColor("#1E293B") : Color.parseColor("#E2E8F0"));
        }
    }

    private GradientDrawable makeRounded(int fill, int stroke, int radiusPx, int strokeWidthPx) {
        GradientDrawable d = new GradientDrawable();
        d.setShape(GradientDrawable.RECTANGLE);
        d.setCornerRadius(radiusPx);
        d.setColor(fill);
        if (strokeWidthPx > 0) {
            d.setStroke(strokeWidthPx, stroke);
        }
        return d;
    }

    private int dp(int v) {
        return Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, v, context.getResources().getDisplayMetrics()));
    }

    private static final class ViewHolder {
        View root;
        TextView methodPill;
        GradientDrawable methodBg;
        TextView hostText;
        TextView statusBadge;
        GradientDrawable statusBg;
        TextView pathText;
        TextView schemeTag;
        GradientDrawable schemeBg;
        TextView latencyText;
        TextView sizeText;
        TextView timeText;
    }
}
