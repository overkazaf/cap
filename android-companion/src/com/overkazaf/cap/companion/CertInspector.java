package com.overkazaf.cap.companion;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Locale;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Inspects Android's live CA trust stores (AndroidCAStore, default
 * X509TrustManager, and Android 14+ APEX Conscrypt / legacy /system paths)
 * without requiring root permissions.
 */
public final class CertInspector {
    private static final String TAG = "CapCertInspector";
    private static final String APEX_CACERTS_DIR = "/apex/com.android.conscrypt/cacerts";
    private static final String SYSTEM_CACERTS_DIR = "/system/etc/security/cacerts";

    private CertInspector() {}

    public static final class CertCheckResult {
        public boolean installed;
        public String store = "none";          // "system", "user", "none"
        public String method = "none";         // "android_ca_store_system", "android_ca_store_user", "trust_manager", "apex_file", "system_file", "legacy_system_only", "none"
        public String alias = "";
        public String hash = "";               // "<hash>.0"
        public String fingerprint = "";        // uppercase colon-separated SHA-256
        public String subject = "";            // CN or DN
        public boolean hasApexDir;
        public boolean legacySystemOnly;
        public boolean fingerprintMismatch;
        public boolean certFileReady;
        public String certFilePath = "";

        public String toKeyValueString() {
            return "installed=" + installed
                    + ";store=" + sanitizeValue(store)
                    + ";method=" + sanitizeValue(method)
                    + ";alias=" + sanitizeValue(alias)
                    + ";hash=" + sanitizeValue(hash)
                    + ";fp=" + sanitizeValue(fingerprint)
                    + ";subject=" + sanitizeValue(subject)
                    + ";apex_dir=" + hasApexDir
                    + ";legacy_only=" + legacySystemOnly
                    + ";fp_mismatch=" + fingerprintMismatch
                    + ";file_ready=" + certFileReady
                    + ";file_path=" + sanitizeValue(certFilePath);
        }

        private static String sanitizeValue(String v) {
            if (v == null) {
                return "";
            }
            return v.replace(';', ',')
                    .replace('"', '\'')
                    .replace('\n', ' ')
                    .replace('\r', ' ')
                    .trim();
        }
    }

    public static CertCheckResult inspect(
            Context ctx,
            String expectedHash,
            String expectedFingerprint,
            String preferredCertPath) {
        CertCheckResult result = new CertCheckResult();
        result.hasApexDir = new File(APEX_CACERTS_DIR).isDirectory();

        // 1. Check local staged cert file (app-private dir, external files dir, Download, /data/local/tmp)
        File certFile = ProxyCleaner.findCertFile(ctx, preferredCertPath);
        if (certFile != null) {
            result.certFileReady = true;
            result.certFilePath = certFile.getAbsolutePath();
        }

        // 2. Resolve expected hash & SHA-256 fingerprint from args -> GuardPrefs -> staged cert file
        String targetHash = normalizeHash(expectedHash);
        String targetFp = normalizeFingerprint(expectedFingerprint);
        if (ctx != null) {
            if (targetHash.isEmpty()) {
                targetHash = normalizeHash(GuardPrefs.getCertHash(ctx));
            }
            if (targetFp.isEmpty()) {
                targetFp = normalizeFingerprint(GuardPrefs.getCertFingerprint(ctx));
            }
        }
        if ((targetHash.isEmpty() || targetFp.isEmpty()) && certFile != null) {
            X509Certificate stagedCert = parseCertFile(certFile);
            if (stagedCert != null) {
                if (targetHash.isEmpty()) {
                    targetHash = normalizeHash(computeSubjectHashOld(stagedCert));
                }
                if (targetFp.isEmpty()) {
                    targetFp = normalizeFingerprint(computeSha256Fingerprint(stagedCert));
                }
            }
        }

        // 3. Primary check: AndroidCAStore (exact same trust store used by Android apps & Conscrypt)
        inspectAndroidCAStore(result, targetHash, targetFp);

        // 4. Secondary check: default X509TrustManager accepted issuers (fallback for exotic OEM ROMs)
        if (!result.installed && !result.fingerprintMismatch) {
            inspectTrustManager(result, targetHash, targetFp);
        }

        // 5. Tertiary filesystem check (catches Android 14+ legacy /system-only & verifies APEX/system paths)
        if (!result.installed && !result.fingerprintMismatch) {
            inspectFilesystemFallback(result, targetHash, targetFp);
        }

        if (result.hash.isEmpty() && !targetHash.isEmpty()) {
            result.hash = targetHash;
        }
        return result;
    }

    private static void inspectAndroidCAStore(CertCheckResult result, String targetHash, String targetFp) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidCAStore");
            ks.load(null, null);

            Match bestMatch = null;
            boolean sawMismatch = false;
            String mismatchHash = "";
            String mismatchFp = "";
            String mismatchSubject = "";

            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (alias == null) {
                    continue;
                }
                Certificate rawCert;
                try {
                    rawCert = ks.getCertificate(alias);
                } catch (Throwable ignored) {
                    continue;
                }
                if (!(rawCert instanceof X509Certificate)) {
                    continue;
                }
                X509Certificate x509 = (X509Certificate) rawCert;

                boolean isSystem = alias.startsWith("system:");
                boolean isUser = alias.startsWith("user:");
                String aliasHash = extractAliasHash(alias);
                String certHash = normalizeHash(computeSubjectHashOld(x509));
                String certFp = computeSha256Fingerprint(x509);
                String normFp = normalizeFingerprint(certFp);
                boolean isCapSubject = isCapMitmCA(x509);

                boolean hashMatches = !targetHash.isEmpty()
                        && (hashBaseEquals(aliasHash, targetHash) || hashBaseEquals(certHash, targetHash));

                int score = 0;
                if (!targetFp.isEmpty()) {
                    if (normFp.equals(targetFp)) {
                        score = isSystem ? 100 : (isUser ? 90 : 80);
                    } else if (isCapSubject || hashMatches) {
                        sawMismatch = true;
                        mismatchHash = !aliasHash.isEmpty() ? aliasHash : certHash;
                        mismatchFp = certFp;
                        mismatchSubject = extractCommonName(x509);
                    }
                } else if (!targetHash.isEmpty()) {
                    if (hashMatches) {
                        score = isSystem ? 85 : (isUser ? 75 : 65);
                    } else if (isCapSubject) {
                        score = isSystem ? 70 : (isUser ? 60 : 50);
                    }
                } else if (isCapSubject) {
                    score = isSystem ? 80 : (isUser ? 70 : 60);
                }

                if (score > 0 && (bestMatch == null || score > bestMatch.score)) {
                    bestMatch = new Match();
                    bestMatch.score = score;
                    bestMatch.store = isSystem ? "system" : (isUser ? "user" : "system");
                    bestMatch.method = isSystem ? "android_ca_store_system" : (isUser ? "android_ca_store_user" : "android_ca_store_system");
                    bestMatch.alias = alias;
                    bestMatch.hash = !aliasHash.isEmpty() ? aliasHash : certHash;
                    bestMatch.fingerprint = certFp;
                    bestMatch.subject = extractCommonName(x509);
                }
            }

            if (bestMatch != null) {
                result.installed = true;
                result.store = bestMatch.store;
                result.method = bestMatch.method;
                result.alias = bestMatch.alias;
                result.hash = bestMatch.hash;
                result.fingerprint = bestMatch.fingerprint;
                result.subject = bestMatch.subject;
            } else if (sawMismatch) {
                result.fingerprintMismatch = true;
                result.hash = mismatchHash;
                result.fingerprint = mismatchFp;
                result.subject = mismatchSubject;
            }
        } catch (Throwable t) {
            Log.w(TAG, "AndroidCAStore inspection failed: " + t.getMessage());
        }
    }

    private static void inspectTrustManager(CertCheckResult result, String targetHash, String targetFp) {
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            TrustManager[] managers = tmf.getTrustManagers();
            if (managers == null) {
                return;
            }
            for (TrustManager tm : managers) {
                if (!(tm instanceof X509TrustManager)) {
                    continue;
                }
                X509Certificate[] issuers = ((X509TrustManager) tm).getAcceptedIssuers();
                if (issuers == null) {
                    continue;
                }
                for (X509Certificate x509 : issuers) {
                    if (x509 == null) {
                        continue;
                    }
                    String certHash = normalizeHash(computeSubjectHashOld(x509));
                    String certFp = computeSha256Fingerprint(x509);
                    String normFp = normalizeFingerprint(certFp);
                    boolean isCapSubject = isCapMitmCA(x509);
                    boolean hashMatches = !targetHash.isEmpty() && hashBaseEquals(certHash, targetHash);

                    boolean matched;
                    if (!targetFp.isEmpty()) {
                        matched = normFp.equals(targetFp);
                    } else if (!targetHash.isEmpty()) {
                        matched = hashMatches || isCapSubject;
                    } else {
                        matched = isCapSubject;
                    }

                    if (matched) {
                        result.installed = true;
                        result.store = "system";
                        result.method = "trust_manager";
                        result.hash = certHash;
                        result.fingerprint = certFp;
                        result.subject = extractCommonName(x509);
                        return;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "TrustManagerFactory inspection failed: " + t.getMessage());
        }
    }

    private static void inspectFilesystemFallback(CertCheckResult result, String targetHash, String targetFp) {
        if (targetHash.isEmpty()) {
            return;
        }
        File apexFile = new File(APEX_CACERTS_DIR, targetHash);
        File systemFile = new File(SYSTEM_CACERTS_DIR, targetHash);

        if (result.hasApexDir) {
            if (apexFile.isFile() && apexFile.canRead()) {
                X509Certificate cert = parseCertFile(apexFile);
                if (cert != null) {
                    String certFp = computeSha256Fingerprint(cert);
                    if (targetFp.isEmpty() || normalizeFingerprint(certFp).equals(targetFp)) {
                        result.installed = true;
                        result.store = "system";
                        result.method = "apex_file";
                        result.hash = targetHash;
                        result.fingerprint = certFp;
                        result.subject = extractCommonName(cert);
                        return;
                    }
                    result.fingerprintMismatch = true;
                    result.hash = targetHash;
                    result.fingerprint = certFp;
                    result.subject = extractCommonName(cert);
                    return;
                }
            }
            if (systemFile.isFile() && systemFile.canRead()) {
                X509Certificate sysCert = parseCertFile(systemFile);
                if (sysCert != null) {
                    // Present ONLY in legacy /system on Android 14+ where APEX Conscrypt is active
                    result.installed = false;
                    result.store = "none";
                    result.method = "legacy_system_only";
                    result.legacySystemOnly = true;
                    result.hash = targetHash;
                    result.fingerprint = computeSha256Fingerprint(sysCert);
                    result.subject = extractCommonName(sysCert);
                }
            }
        } else if (systemFile.isFile() && systemFile.canRead()) {
            X509Certificate cert = parseCertFile(systemFile);
            if (cert != null) {
                String certFp = computeSha256Fingerprint(cert);
                if (targetFp.isEmpty() || normalizeFingerprint(certFp).equals(targetFp)) {
                    result.installed = true;
                    result.store = "system";
                    result.method = "system_file";
                    result.hash = targetHash;
                    result.fingerprint = certFp;
                    result.subject = extractCommonName(cert);
                    return;
                }
                result.fingerprintMismatch = true;
                result.hash = targetHash;
                result.fingerprint = certFp;
                result.subject = extractCommonName(cert);
            }
        }
    }

    public static X509Certificate parseCertBytes(byte[] data) {
        if (data == null || data.length == 0) {
            return null;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(data));
            if (cert instanceof X509Certificate) {
                return (X509Certificate) cert;
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    public static X509Certificate parseCertFile(File file) {
        if (file == null || !file.isFile() || !file.canRead()) {
            return null;
        }
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(in);
            if (cert instanceof X509Certificate) {
                return (X509Certificate) cert;
            }
        } catch (Throwable ignored) {
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    /**
     * Computes OpenSSL's legacy subject_hash_old ("<8-hex>.0"), matching
     * Android's native cacerts filename convention.
     */
    public static String computeSubjectHashOld(X509Certificate cert) {
        if (cert == null) {
            return "";
        }
        try {
            byte[] encoded = cert.getSubjectX500Principal().getEncoded();
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] digest = md5.digest(encoded);
            long val = ((long) (digest[0] & 0xff))
                    | (((long) (digest[1] & 0xff)) << 8)
                    | (((long) (digest[2] & 0xff)) << 16)
                    | (((long) (digest[3] & 0xff)) << 24);
            return String.format(Locale.US, "%08x.0", val);
        } catch (Throwable t) {
            return "";
        }
    }

    public static String computeSha256Fingerprint(X509Certificate cert) {
        if (cert == null) {
            return "";
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder(digest.length * 3);
            for (int i = 0; i < digest.length; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(String.format(Locale.US, "%02X", digest[i] & 0xff));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    public static boolean isCapMitmCA(X509Certificate cert) {
        if (cert == null) {
            return false;
        }
        // Only match actual CA certificates
        if (cert.getBasicConstraints() < 0) {
            return false;
        }
        String cn = extractCommonName(cert);
        if ("Cap MITM CA".equalsIgnoreCase(cn)) {
            return true;
        }
        String org = extractRdnValue(cert.getSubjectX500Principal(), "O");
        return ("cap".equalsIgnoreCase(org) || "cap-test".equalsIgnoreCase(org))
                && cn.toLowerCase(Locale.US).contains("cap")
                && cn.toLowerCase(Locale.US).contains("ca");
    }

    public static String extractCommonName(X509Certificate cert) {
        if (cert == null) {
            return "";
        }
        X500Principal principal = cert.getSubjectX500Principal();
        String cn = extractRdnValue(principal, "CN");
        return !cn.isEmpty() ? cn : principal.getName();
    }

    private static String extractRdnValue(X500Principal principal, String key) {
        if (principal == null || key == null) {
            return "";
        }
        String dn = principal.getName(X500Principal.RFC2253);
        if (dn == null || dn.isEmpty()) {
            return "";
        }
        String prefix = key.toUpperCase(Locale.US) + "=";
        int len = dn.length();
        int start = 0;
        boolean escaped = false;
        for (int i = 0; i <= len; i++) {
            char c = i < len ? dn.charAt(i) : ',';
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == ',' || c == '+') {
                String token = dn.substring(start, i).trim();
                if (token.toUpperCase(Locale.US).startsWith(prefix)) {
                    return unescapeRdn(token.substring(prefix.length()).trim());
                }
                start = i + 1;
            }
        }
        return "";
    }

    private static String unescapeRdn(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' && i + 1 < raw.length()) {
                sb.append(raw.charAt(++i));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String extractAliasHash(String alias) {
        int idx = alias.indexOf(':');
        if (idx >= 0 && idx + 1 < alias.length()) {
            return normalizeHash(alias.substring(idx + 1));
        }
        return "";
    }

    public static String normalizeHash(String hash) {
        if (hash == null) {
            return "";
        }
        String h = hash.trim().toLowerCase(Locale.US);
        if (h.isEmpty()) {
            return "";
        }
        if (h.matches("^[0-9a-f]{8}$")) {
            return h + ".0";
        }
        if (h.matches("^[0-9a-f]{8}\\.[0-9]+$")) {
            return h;
        }
        return "";
    }

    private static boolean hashBaseEquals(String a, String b) {
        if (a == null || b == null || a.isEmpty() || b.isEmpty()) {
            return false;
        }
        if (a.equalsIgnoreCase(b)) {
            return true;
        }
        String baseA = a.contains(".") ? a.substring(0, a.indexOf('.')) : a;
        String baseB = b.contains(".") ? b.substring(0, b.indexOf('.')) : b;
        return baseA.length() == 8 && baseA.equalsIgnoreCase(baseB);
    }

    public static String normalizeFingerprint(String fp) {
        if (fp == null) {
            return "";
        }
        return fp.replace(":", "").replace(" ", "").trim().toUpperCase(Locale.US);
    }

    private static final class Match {
        int score;
        String store;
        String method;
        String alias;
        String hash;
        String fingerprint;
        String subject;
    }
}
