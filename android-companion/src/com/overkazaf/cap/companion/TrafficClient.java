package com.overkazaf.cap.companion;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Lightweight HTTP client for Cap's direct in-proxy companion traffic API
 * ({@code http://<proxyHost>:<proxyPort>/_cap/companion/...}).
 *
 * All connections strictly use {@link Proxy#NO_PROXY} so polling requests talk
 * directly to the proxy server and never loop back through Android's global
 * HTTP proxy. Pure Java + {@code org.json} so parsing and formatting helpers
 * can also be verified directly on the JVM.
 */
public final class TrafficClient {
    public static final int CONNECT_TIMEOUT_MS = 2500;
    public static final int READ_TIMEOUT_MS = 3500;
    public static final int MAX_RESPONSE_BYTES = 512 * 1024; // 512 KiB strict cap

    private TrafficClient() {}

    public enum ErrorKind {
        NONE,
        NO_PROXY_ENDPOINT,
        UNAUTHORIZED,
        OFFLINE,
        API_ERROR
    }

    public static class FlowSummary {
        public long seq;
        public String id = "";
        public String method = "";
        public String scheme = "";
        public String host = "";
        public String path = "";
        public String url = "";
        public int status;
        public String contentType = "";
        public long reqBytes;
        public long respBytes;
        public long latencyMs;
        public long timestampMs;
        public String error = "";
    }

    public static final class FlowDetail extends FlowSummary {
        public Map<String, String> reqHeaders = new LinkedHashMap<String, String>();
        public Map<String, String> respHeaders = new LinkedHashMap<String, String>();
        public String reqBody = "";
        public String respBody = "";
        public boolean reqBodyTruncated;
        public boolean respBodyTruncated;
        public boolean reqBodyBinary;
        public boolean respBodyBinary;
    }

    public static final class FlowsResult {
        public boolean ok;
        public ErrorKind errorKind = ErrorKind.NONE;
        public String errorMessage = "";
        public int httpStatus;
        public long latestSeq;
        public long totalFlows;
        public int bufferedFlows;
        public long totalBytes;
        public double reqPerSec;
        public List<FlowSummary> flows = new ArrayList<FlowSummary>();
    }

    public static final class FlowDetailResult {
        public boolean ok;
        public ErrorKind errorKind = ErrorKind.NONE;
        public String errorMessage = "";
        public int httpStatus;
        public FlowDetail flow;
    }

    public static final class ClearResult {
        public boolean ok;
        public ErrorKind errorKind = ErrorKind.NONE;
        public String errorMessage = "";
        public int httpStatus;
        public long latestSeq;
    }

    private static final class RawHttpResponse {
        int statusCode;
        String body = "";
        ErrorKind errorKind = ErrorKind.NONE;
        String errorMessage = "";
    }

    /**
     * Resolves the effective proxy endpoint ({@code host:port}) in priority order:
     * manual override -> active system global proxy -> running watchdog -> saved prefs.
     */
    public static String resolveEndpoint(
            String customOverride,
            String globalProxy,
            String runningHost,
            int runningPort,
            String savedHost,
            int savedPort) {
        String custom = normalizeEndpoint(customOverride);
        if (!custom.isEmpty()) {
            return custom;
        }
        return resolveAutoEndpoint(globalProxy, runningHost, runningPort, savedHost, savedPort);
    }

    public static String resolveAutoEndpoint(
            String globalProxy,
            String runningHost,
            int runningPort,
            String savedHost,
            int savedPort) {
        String global = normalizeEndpoint(globalProxy);
        if (!global.isEmpty()) {
            return global;
        }
        if (runningHost != null && !runningHost.trim().isEmpty() && runningPort > 0 && runningPort <= 65535) {
            String ep = normalizeEndpoint(runningHost.trim() + ":" + runningPort);
            if (!ep.isEmpty()) {
                return ep;
            }
        }
        if (savedHost != null && !savedHost.trim().isEmpty() && savedPort > 0 && savedPort <= 65535) {
            String ep = normalizeEndpoint(savedHost.trim() + ":" + savedPort);
            if (!ep.isEmpty()) {
                return ep;
            }
        }
        return "";
    }

    /**
     * Normalizes a user- or system-supplied proxy string into {@code host:port}
     * (or {@code [ipv6]:port}). Returns empty string if invalid.
     */
    public static String normalizeEndpoint(String raw) {
        if (raw == null) {
            return "";
        }
        String s = raw.trim();
        if (s.isEmpty() || ":0".equals(s) || ":".equals(s) || "0".equals(s) || "null".equalsIgnoreCase(s)) {
            return "";
        }
        String lower = s.toLowerCase(Locale.US);
        if (lower.startsWith("http://")) {
            s = s.substring(7);
        } else if (lower.startsWith("https://")) {
            s = s.substring(8);
        }
        int slash = s.indexOf('/');
        if (slash >= 0) {
            s = s.substring(0, slash);
        }
        s = s.trim();
        int colon = s.lastIndexOf(':');
        if (colon <= 0 || colon >= s.length() - 1) {
            return "";
        }
        String host = s.substring(0, colon).trim();
        String portStr = s.substring(colon + 1).trim();
        if (host.isEmpty()) {
            return "";
        }
        boolean bracketed = host.startsWith("[") && host.endsWith("]") && host.length() > 2;
        String bareHost = bracketed ? host.substring(1, host.length() - 1) : host;
        if (bareHost.isEmpty() || bareHost.contains(" ") || bareHost.contains("\t") || bareHost.contains("@")) {
            return "";
        }
        int port;
        try {
            port = Integer.parseInt(portStr);
        } catch (NumberFormatException e) {
            return "";
        }
        if (port <= 0 || port > 65535) {
            return "";
        }
        if (bareHost.contains(":")) {
            return "[" + bareHost + "]:" + port;
        }
        return bareHost + ":" + port;
    }

    /**
     * Returns the USB ADB-reverse loopback fallback endpoint ({@code 127.0.0.1:<port>})
     * for a non-loopback primary endpoint, or empty string if {@code primaryEndpoint}
     * is invalid or already points to loopback.
     */
    public static String loopbackFallbackEndpoint(String primaryEndpoint) {
        String norm = normalizeEndpoint(primaryEndpoint);
        if (norm.isEmpty()) {
            return "";
        }
        int colon = norm.lastIndexOf(':');
        if (colon <= 0 || colon >= norm.length() - 1) {
            return "";
        }
        String host = norm.substring(0, colon);
        String port = norm.substring(colon + 1);
        if ("127.0.0.1".equals(host)
                || "localhost".equalsIgnoreCase(host)
                || "[::1]".equals(host)
                || "::1".equals(host)) {
            return "";
        }
        return "127.0.0.1:" + port;
    }

    /**
     * Produces a concise single-line error reason suitable for status hints and toasts.
     */
    public static String formatErrorBrief(String rawError) {
        if (rawError == null) {
            return "";
        }
        String clean = rawError.replace('\r', ' ').replace('\n', ' ').trim();
        while (clean.contains("  ")) {
            clean = clean.replace("  ", " ");
        }
        if (clean.length() > 96) {
            clean = clean.substring(0, 93) + "...";
        }
        return clean;
    }

    public static FlowsResult fetchFlows(
            String endpoint,
            String apiToken,
            int limit,
            long afterSeq,
            String method,
            String search,
            String statusGroup,
            String scheme) {
        String normalized = normalizeEndpoint(endpoint);
        if (normalized.isEmpty()) {
            FlowsResult res = new FlowsResult();
            res.errorKind = ErrorKind.NO_PROXY_ENDPOINT;
            res.errorMessage = "No proxy endpoint configured";
            return res;
        }

        int clampedLimit = Math.max(1, Math.min(200, limit));
        StringBuilder url = new StringBuilder("http://").append(normalized).append("/_cap/companion/flows?");
        url.append("limit=").append(clampedLimit);
        url.append("&after=").append(Math.max(0L, afterSeq));
        url.append("&method=").append(urlEncode(method));
        url.append("&search=").append(urlEncode(search));
        url.append("&status_group=").append(urlEncode(statusGroup));
        url.append("&scheme=").append(urlEncode(scheme));

        RawHttpResponse raw = executeRequest("GET", url.toString(), apiToken);
        if (raw.errorKind != ErrorKind.NONE) {
            FlowsResult res = new FlowsResult();
            res.errorKind = raw.errorKind;
            res.errorMessage = raw.errorMessage;
            res.httpStatus = raw.statusCode;
            return res;
        }
        FlowsResult parsed = parseFlowsJson(raw.body);
        parsed.httpStatus = raw.statusCode;
        return parsed;
    }

    public static FlowDetailResult fetchFlowDetail(String endpoint, String apiToken, String flowId) {
        String normalized = normalizeEndpoint(endpoint);
        if (normalized.isEmpty()) {
            FlowDetailResult res = new FlowDetailResult();
            res.errorKind = ErrorKind.NO_PROXY_ENDPOINT;
            res.errorMessage = "No proxy endpoint configured";
            return res;
        }
        if (flowId == null || flowId.trim().isEmpty()) {
            FlowDetailResult res = new FlowDetailResult();
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Missing flow ID";
            return res;
        }
        String encodedId = urlEncode(flowId.trim()).replace("+", "%20");
        String url = "http://" + normalized + "/_cap/companion/flows/" + encodedId;
        RawHttpResponse raw = executeRequest("GET", url, apiToken);
        if (raw.errorKind != ErrorKind.NONE) {
            FlowDetailResult res = new FlowDetailResult();
            res.errorKind = raw.errorKind;
            res.errorMessage = raw.errorMessage;
            res.httpStatus = raw.statusCode;
            return res;
        }
        FlowDetailResult parsed = parseFlowDetailJson(raw.body);
        parsed.httpStatus = raw.statusCode;
        return parsed;
    }

    public static ClearResult clearFlows(String endpoint, String apiToken) {
        String normalized = normalizeEndpoint(endpoint);
        if (normalized.isEmpty()) {
            ClearResult res = new ClearResult();
            res.errorKind = ErrorKind.NO_PROXY_ENDPOINT;
            res.errorMessage = "No proxy endpoint configured";
            return res;
        }
        String url = "http://" + normalized + "/_cap/companion/clear";
        RawHttpResponse raw = executeRequest("POST", url, apiToken);
        if (raw.errorKind != ErrorKind.NONE) {
            ClearResult res = new ClearResult();
            res.errorKind = raw.errorKind;
            res.errorMessage = raw.errorMessage;
            res.httpStatus = raw.statusCode;
            return res;
        }
        ClearResult parsed = parseClearJson(raw.body);
        parsed.httpStatus = raw.statusCode;
        return parsed;
    }

    private static RawHttpResponse executeRequest(String httpMethod, String urlStr, String apiToken) {
        RawHttpResponse out = new RawHttpResponse();
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            // CRITICAL: Always bypass device global proxy so requests go directly to Cap proxy.
            conn = (HttpURLConnection) url.openConnection(Proxy.NO_PROXY);
            conn.setRequestMethod(httpMethod);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setUseCaches(false);
            conn.setInstanceFollowRedirects(false);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Connection", "close");
            if (apiToken != null && !apiToken.trim().isEmpty()) {
                conn.setRequestProperty("X-Cap-Token", apiToken.trim());
            }
            if ("POST".equals(httpMethod)) {
                conn.setDoOutput(true);
                conn.setFixedLengthStreamingMode(0);
                conn.getOutputStream().close();
            }

            int code = conn.getResponseCode();
            out.statusCode = code;

            InputStream stream = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
            if (stream != null) {
                try {
                    out.body = readBoundedUtf8(stream, MAX_RESPONSE_BYTES);
                } catch (ResponseTooLargeException tooLarge) {
                    out.errorKind = ErrorKind.API_ERROR;
                    out.errorMessage = tooLarge.getMessage();
                    return out;
                } finally {
                    try {
                        stream.close();
                    } catch (Throwable ignored) {
                    }
                }
            }

            if (code == 401) {
                out.errorKind = ErrorKind.UNAUTHORIZED;
                out.errorMessage = extractJsonError(out.body, "unauthorized");
                return out;
            }
            if (code < 200 || code >= 300) {
                out.errorKind = ErrorKind.API_ERROR;
                out.errorMessage = extractJsonError(out.body, "HTTP " + code);
                return out;
            }
            out.errorKind = ErrorKind.NONE;
            return out;
        } catch (IOException ioe) {
            out.errorKind = ErrorKind.OFFLINE;
            out.errorMessage = ioe.getMessage() != null ? ioe.getMessage() : ioe.getClass().getSimpleName();
            return out;
        } catch (Throwable t) {
            out.errorKind = ErrorKind.API_ERROR;
            out.errorMessage = t.getMessage() != null ? t.getMessage() : t.getClass().getSimpleName();
            return out;
        } finally {
            if (conn != null) {
                try {
                    conn.disconnect();
                } catch (Throwable ignored) {
                }
            }
        }
    }

    private static final class ResponseTooLargeException extends IOException {
        ResponseTooLargeException(int limitBytes) {
            super("Response exceeded " + (limitBytes / 1024) + " KiB limit");
        }
    }

    private static String readBoundedUtf8(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while ((n = in.read(buf)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new ResponseTooLargeException(maxBytes);
            }
            baos.write(buf, 0, n);
        }
        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    // ==================== JSON Parsers (Pure & Unit-Testable) ====================

    public static FlowsResult parseFlowsJson(String json) {
        FlowsResult res = new FlowsResult();
        if (json == null || json.trim().isEmpty()) {
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Empty JSON response";
            return res;
        }
        try {
            JSONObject root = new JSONObject(json);
            if (!root.optBoolean("ok", false)) {
                res.errorKind = ErrorKind.API_ERROR;
                res.errorMessage = safeString(root, "error");
                if (res.errorMessage.isEmpty()) {
                    res.errorMessage = "API returned ok=false";
                }
                return res;
            }
            res.ok = true;
            res.errorKind = ErrorKind.NONE;
            res.latestSeq = root.optLong("latest_seq", 0L);
            res.totalFlows = root.optLong("total_flows", 0L);
            res.bufferedFlows = root.optInt("buffered_flows", 0);
            res.totalBytes = root.optLong("total_bytes", 0L);
            res.reqPerSec = root.optDouble("req_per_sec", 0.0);
            if (Double.isNaN(res.reqPerSec) || Double.isInfinite(res.reqPerSec) || res.reqPerSec < 0) {
                res.reqPerSec = 0.0;
            }

            JSONArray arr = root.optJSONArray("flows");
            if (arr != null) {
                List<FlowSummary> list = new ArrayList<FlowSummary>(arr.length());
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject item = arr.optJSONObject(i);
                    if (item != null) {
                        FlowSummary f = new FlowSummary();
                        populateSummary(f, item);
                        list.add(f);
                    }
                }
                res.flows = list;
            }
            return res;
        } catch (JSONException je) {
            res.ok = false;
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Invalid JSON: " + (je.getMessage() != null ? je.getMessage() : "parse error");
            return res;
        }
    }

    public static FlowDetailResult parseFlowDetailJson(String json) {
        FlowDetailResult res = new FlowDetailResult();
        if (json == null || json.trim().isEmpty()) {
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Empty JSON response";
            return res;
        }
        try {
            JSONObject root = new JSONObject(json);
            if (!root.optBoolean("ok", false)) {
                res.errorKind = ErrorKind.API_ERROR;
                res.errorMessage = safeString(root, "error");
                if (res.errorMessage.isEmpty()) {
                    res.errorMessage = "API returned ok=false";
                }
                return res;
            }
            JSONObject obj = root.optJSONObject("flow");
            if (obj == null) {
                res.errorKind = ErrorKind.API_ERROR;
                res.errorMessage = "Missing flow payload";
                return res;
            }
            FlowDetail detail = new FlowDetail();
            populateSummary(detail, obj);
            detail.reqHeaders = parseHeadersMap(obj.optJSONObject("req_headers"));
            detail.respHeaders = parseHeadersMap(obj.optJSONObject("resp_headers"));
            detail.reqBody = safeString(obj, "req_body");
            detail.respBody = safeString(obj, "resp_body");
            detail.reqBodyTruncated = obj.optBoolean("req_body_truncated", false);
            detail.respBodyTruncated = obj.optBoolean("resp_body_truncated", false);
            detail.reqBodyBinary = obj.optBoolean("req_body_binary", false);
            detail.respBodyBinary = obj.optBoolean("resp_body_binary", false);

            res.ok = true;
            res.errorKind = ErrorKind.NONE;
            res.flow = detail;
            return res;
        } catch (JSONException je) {
            res.ok = false;
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Invalid JSON: " + (je.getMessage() != null ? je.getMessage() : "parse error");
            return res;
        }
    }

    public static ClearResult parseClearJson(String json) {
        ClearResult res = new ClearResult();
        if (json == null || json.trim().isEmpty()) {
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Empty JSON response";
            return res;
        }
        try {
            JSONObject root = new JSONObject(json);
            if (!root.optBoolean("ok", false)) {
                res.errorKind = ErrorKind.API_ERROR;
                res.errorMessage = safeString(root, "error");
                if (res.errorMessage.isEmpty()) {
                    res.errorMessage = "API returned ok=false";
                }
                return res;
            }
            res.ok = true;
            res.errorKind = ErrorKind.NONE;
            res.latestSeq = root.optLong("latest_seq", 0L);
            return res;
        } catch (JSONException je) {
            res.ok = false;
            res.errorKind = ErrorKind.API_ERROR;
            res.errorMessage = "Invalid JSON: " + (je.getMessage() != null ? je.getMessage() : "parse error");
            return res;
        }
    }

    private static void populateSummary(FlowSummary f, JSONObject obj) {
        f.seq = obj.optLong("seq", 0L);
        f.id = safeString(obj, "id");
        f.method = safeString(obj, "method").toUpperCase(Locale.US);
        f.scheme = safeString(obj, "scheme").toLowerCase(Locale.US);
        f.host = safeString(obj, "host");
        f.path = safeString(obj, "path");
        f.url = safeString(obj, "url");
        f.status = obj.optInt("status", 0);
        f.contentType = safeString(obj, "content_type");
        f.reqBytes = obj.optLong("req_bytes", 0L);
        f.respBytes = obj.optLong("resp_bytes", 0L);
        f.latencyMs = obj.optLong("latency_ms", 0L);
        f.timestampMs = obj.optLong("timestamp_ms", 0L);
        f.error = safeString(obj, "error");
    }

    private static Map<String, String> parseHeadersMap(JSONObject obj) {
        Map<String, String> map = new LinkedHashMap<String, String>();
        if (obj == null) {
            return map;
        }
        Iterator<String> keys = obj.keys();
        while (keys.hasNext()) {
            String k = keys.next();
            if (k != null) {
                map.put(k, safeString(obj, k));
            }
        }
        return map;
    }

    private static String safeString(JSONObject obj, String key) {
        if (obj == null || key == null || obj.isNull(key)) {
            return "";
        }
        String val = obj.optString(key, "");
        return val != null ? val : "";
    }

    private static String extractJsonError(String body, String fallback) {
        if (body != null && !body.trim().isEmpty()) {
            try {
                JSONObject obj = new JSONObject(body);
                String err = safeString(obj, "error");
                if (!err.isEmpty()) {
                    return err;
                }
            } catch (Throwable ignored) {
            }
        }
        return fallback;
    }

    // ==================== Formatting & Export Helpers ====================

    /**
     * Pretty-prints JSON objects/arrays with 2-space indentation; falls back
     * cleanly to the original raw text for non-JSON or malformed payloads.
     */
    public static String prettyPrintBody(String body, String contentType) {
        if (body == null || body.isEmpty()) {
            return "";
        }
        String trimmed = body.trim();
        if (trimmed.isEmpty()) {
            return body;
        }
        boolean jsonHint = contentType != null && contentType.toLowerCase(Locale.US).contains("json");
        boolean startsObject = trimmed.startsWith("{");
        boolean startsArray = trimmed.startsWith("[");
        if (!jsonHint && !startsObject && !startsArray) {
            return body;
        }
        try {
            if (startsObject) {
                return new JSONObject(trimmed).toString(2);
            }
            if (startsArray) {
                return new JSONArray(trimmed).toString(2);
            }
        } catch (JSONException ignored) {
        }
        return body;
    }

    /**
     * Builds a safe POSIX-escaped cURL command for a captured flow.
     */
    public static String buildCurlCommand(FlowDetail detail) {
        if (detail == null) {
            return "";
        }
        String method = (detail.method == null || detail.method.trim().isEmpty())
                ? "GET"
                : detail.method.trim().toUpperCase(Locale.US);
        String url = resolveFullUrl(detail);
        if (url.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("curl -X ").append(method).append(" '").append(shellSingleQuoteEscape(url)).append("'");

        if (detail.reqHeaders != null) {
            for (Map.Entry<String, String> entry : detail.reqHeaders.entrySet()) {
                String k = entry.getKey();
                if (k == null || k.trim().isEmpty()) {
                    continue;
                }
                String key = k.trim();
                if (key.startsWith(":") || "content-length".equalsIgnoreCase(key)) {
                    continue;
                }
                String v = entry.getValue() != null ? entry.getValue() : "";
                sb.append(" \\\n  -H '")
                        .append(shellSingleQuoteEscape(key + ": " + v))
                        .append("'");
            }
        }

        if (detail.reqBody != null && !detail.reqBody.isEmpty() && !detail.reqBodyBinary) {
            sb.append(" \\\n  --data-raw '")
                    .append(shellSingleQuoteEscape(detail.reqBody))
                    .append("'");
        }
        return sb.toString();
    }

    public static String resolveFullUrl(FlowSummary f) {
        if (f == null) {
            return "";
        }
        if (f.url != null && !f.url.trim().isEmpty()) {
            return f.url.trim();
        }
        if (f.host == null || f.host.trim().isEmpty()) {
            return "";
        }
        String scheme = (f.scheme == null || f.scheme.trim().isEmpty()) ? "http" : f.scheme.trim();
        String path = (f.path == null || f.path.isEmpty()) ? "/" : f.path;
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return scheme + "://" + f.host.trim() + path;
    }

    public static String findHeaderIgnoreCase(Map<String, String> headers, String targetName) {
        if (headers == null || targetName == null) {
            return "";
        }
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() != null && targetName.equalsIgnoreCase(e.getKey().trim())) {
                return e.getValue() != null ? e.getValue() : "";
            }
        }
        return "";
    }

    public static String formatBytes(long bytes) {
        if (bytes <= 0) {
            return "0 B";
        }
        if (bytes < 1024L) {
            return bytes + " B";
        }
        if (bytes < 1024L * 1024L) {
            return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024L * 1024L) {
            return String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0));
        }
        return String.format(Locale.US, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    public static String formatLatency(long ms) {
        if (ms < 0) {
            return "-";
        }
        if (ms < 1000L) {
            return ms + " ms";
        }
        return String.format(Locale.US, "%.2f s", ms / 1000.0);
    }

    public static String formatRate(double reqPerSec) {
        if (Double.isNaN(reqPerSec) || Double.isInfinite(reqPerSec) || reqPerSec <= 0.0) {
            return "0.0/s";
        }
        if (reqPerSec < 10.0) {
            return String.format(Locale.US, "%.1f/s", reqPerSec);
        }
        return String.format(Locale.US, "%.0f/s", reqPerSec);
    }

    public static String formatTimestamp(long timestampMs) {
        if (timestampMs <= 0L) {
            return "";
        }
        return new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date(timestampMs));
    }

    private static String shellSingleQuoteEscape(String s) {
        return s.replace("'", "'\\''");
    }

    private static String urlEncode(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return "";
        }
    }
}
