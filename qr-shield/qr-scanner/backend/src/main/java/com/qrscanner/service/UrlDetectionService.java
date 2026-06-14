package com.qrscanner.service;

import com.qrscanner.model.ThreatResult;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.*;

/**
 * UrlDetectionService — the core threat-scoring engine.
 *
 * ARCHITECTURE:
 *   Each check returns a partial score (0-N) added to a running totalScore.
 *   Final verdict is derived from totalScore vs. calibrated thresholds.
 *   Confidence = how many independent signals fired (multi-signal = high confidence).
 *
 * BUG-FIX SUMMARY (vs. naive/broken baseline):
 *  1. Blacklist was checked but score was never accumulated  → fixed, +50 pts
 *  2. Phishing keywords matched case-insensitively but returned 0 → fixed, +30 pts each keyword
 *  3. SSL check was inverted (HTTP was flagged as SAFE)        → fixed
 *  4. Typosquatting threshold was too loose (edit-distance ≤ 5) → tightened to ≤ 2
 *  5. IP-address URLs always scored 0                          → fixed, +40 pts
 *  6. URL shorteners returned SAFE without redirect analysis   → fixed, +25 pts + indicator
 *  7. Newly registered domain check was missing entirely       → added heuristic
 *  8. Verdict thresholds were SAFE<80, SUSPICIOUS<90, rest MALICIOUS → inverted/wrong → fixed
 *  9. Confidence was always 100 regardless of signal count     → fixed, proportional
 * 10. Homograph / IDN attack detection was absent              → added
 */
@Service
public class UrlDetectionService {

    // ── Hardcoded blacklist (production would call Google Safe Browsing / VirusTotal) ──
    private static final Set<String> BLACKLISTED_DOMAINS = new HashSet<>(Arrays.asList(
        "malware-site.com", "phishing-bank.com", "secure-paypal-login.tk",
        "account-verify-amazon.xyz", "apple-id-suspended.ml", "paypal-secure-login.cf",
        "microsoft-support-alert.gq", "netflix-billing-update.tk", "login-facebook-secure.ml",
        "bankofamerica-verify.xyz", "chase-bank-alert.cf", "irs-tax-refund.tk",
        "fedex-parcel-track.ml", "dhl-delivery-confirm.gq", "covid-relief-fund.xyz",
        "free-iphone-winner.tk", "crypto-investment-guaranteed.ml", "bit.ly-malware.com"
    ));

    // ── Known legitimate domains (whitelist core TLDs only — not a bypass, used to reduce FP) ──
    private static final Set<String> TRUSTED_DOMAINS = new HashSet<>(Arrays.asList(
        "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "twitter.com", "instagram.com", "linkedin.com", "github.com",
        "wikipedia.org", "reddit.com", "netflix.com", "paypal.com", "ebay.com",
        "stackoverflow.com", "anthropic.com", "openai.com", "cloudflare.com"
    ));

    // ── URL shorteners — never safe without further analysis ──
    private static final Set<String> URL_SHORTENERS = new HashSet<>(Arrays.asList(
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
        "adf.ly", "shorte.st", "bc.vc", "sh.st", "linkbucks.com",
        "ouo.io", "exe.io", "clk.sh", "clkme.me"
    ));

    // ── Suspicious TLDs commonly abused in phishing ──
    private static final Set<String> SUSPICIOUS_TLDS = new HashSet<>(Arrays.asList(
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
        ".online", ".site", ".website", ".space", ".pw", ".cc",
        ".biz.pk", ".icu", ".vip", ".win", ".bid", ".review", ".loan"
    ));

    // ── Brands commonly spoofed — if URL contains these but domain ≠ brand domain ──
    private static final Map<String, String> BRAND_DOMAINS = new LinkedHashMap<>();
    static {
        BRAND_DOMAINS.put("paypal",    "paypal.com");
        BRAND_DOMAINS.put("apple",     "apple.com");
        BRAND_DOMAINS.put("microsoft", "microsoft.com");
        BRAND_DOMAINS.put("amazon",    "amazon.com");
        BRAND_DOMAINS.put("google",    "google.com");
        BRAND_DOMAINS.put("facebook",  "facebook.com");
        BRAND_DOMAINS.put("netflix",   "netflix.com");
        BRAND_DOMAINS.put("instagram", "instagram.com");
        BRAND_DOMAINS.put("twitter",   "twitter.com");
        BRAND_DOMAINS.put("chase",     "chase.com");
        BRAND_DOMAINS.put("wellsfargo","wellsfargo.com");
        BRAND_DOMAINS.put("citibank",  "citibank.com");
        BRAND_DOMAINS.put("bankofamerica", "bankofamerica.com");
        BRAND_DOMAINS.put("irs",       "irs.gov");
        BRAND_DOMAINS.put("fedex",     "fedex.com");
        BRAND_DOMAINS.put("dhl",       "dhl.com");
        BRAND_DOMAINS.put("ups",       "ups.com");
    }

    // ── Phishing keyword patterns ──
    private static final List<String> PHISHING_KEYWORDS = Arrays.asList(
        "login", "signin", "sign-in", "account", "verify", "verification",
        "secure", "security", "update", "confirm", "password", "credential",
        "banking", "wallet", "billing", "payment", "invoice", "suspended",
        "locked", "unlock", "limited", "alert", "warning", "urgent",
        "validate", "authenticate", "recover", "restore", "reactivate"
    );

    // ── Suspicious path patterns ──
    private static final List<Pattern> SUSPICIOUS_PATH_PATTERNS = Arrays.asList(
        Pattern.compile("\\.(exe|bat|ps1|vbs|js|jar|msi|dmg|apk)$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/(download|install|setup|run|execute)/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/wp-admin/|/admin/|/phpmyadmin/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("base64,", Pattern.CASE_INSENSITIVE),
        Pattern.compile("%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", Pattern.CASE_INSENSITIVE) // triple-encoded
    );

    // ── Regex helpers ──
    private static final Pattern IP_PATTERN =
        Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");
    private static final Pattern HOMOGRAPH_PATTERN =
        Pattern.compile("[^\u0000-\u007F]"); // non-ASCII in hostname

    // ── Verdict thresholds (FIXED — previous code had these backwards) ──
    private static final int SAFE_THRESHOLD       = 15;   // 0-15  → SAFE
    private static final int SUSPICIOUS_THRESHOLD = 45;   // 16-45 → SUSPICIOUS
                                                           // 46+   → MALICIOUS

    // ─────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ─────────────────────────────────────────────────────────────────

    public ThreatResult analyze(String rawUrl) {
        long start = System.currentTimeMillis();
        ThreatResult result = new ThreatResult();
        result.setUrl(rawUrl);

        // ── 1. Normalize & parse ──
        String url = normalizeUrl(rawUrl);
        ParsedUrl parsed;
        try {
            parsed = parseUrl(url);
        } catch (Exception e) {
            result.setVerdict("MALICIOUS");
            result.setThreatScore(95);
            result.setConfidenceScore(90);
            result.getThreats().add("URL_PARSE_FAILURE: Cannot parse URL structure");
            result.setRecommendation("This URL is malformed or obfuscated. Do not visit.");
            result.setScanDurationMs(System.currentTimeMillis() - start);
            return result;
        }

        int score = 0;
        int signalCount = 0;

        // ── 2. Build DomainInfo ──
        ThreatResult.DomainInfo domainInfo = buildDomainInfo(parsed);
        result.setDomainInfo(domainInfo);

        // ── 3. Build SslInfo ──
        ThreatResult.SslInfo sslInfo = buildSslInfo(parsed, url);
        result.setSslInfo(sslInfo);

        // ══════════════════════════════════════════════
        //  DETECTION CHECKS — each returns partial score
        // ══════════════════════════════════════════════

        // [A] Blacklist check — highest priority, instant MALICIOUS
        int blacklistScore = checkBlacklist(parsed, result);
        if (blacklistScore > 0) { score += blacklistScore; signalCount += 3; }

        // [B] IP-address as host (BUG FIX: was always 0)
        int ipScore = checkIpAddress(parsed, result);
        if (ipScore > 0) { score += ipScore; signalCount++; }

        // [C] Homograph / IDN spoofing
        int homographScore = checkHomograph(parsed, result, domainInfo);
        if (homographScore > 0) { score += homographScore; signalCount++; }

        // [D] Suspicious TLD
        int tldScore = checkSuspiciousTld(parsed, result, domainInfo);
        if (tldScore > 0) { score += tldScore; signalCount++; }

        // [E] Brand impersonation / typosquatting (BUG FIX: threshold was too loose)
        int brandScore = checkBrandImpersonation(parsed, url, result);
        if (brandScore > 0) { score += brandScore; signalCount += 2; }

        // [F] SSL check (BUG FIX: was inverted)
        int sslScore = checkSsl(parsed, sslInfo, result);
        if (sslScore > 0) { score += sslScore; signalCount++; }

        // [G] URL shortener (BUG FIX: was returning SAFE)
        int shortenerScore = checkUrlShortener(parsed, result);
        if (shortenerScore > 0) { score += shortenerScore; signalCount++; }

        // [H] Phishing keywords in URL (BUG FIX: was returning 0 even on match)
        int phishingScore = checkPhishingKeywords(url, parsed, result);
        if (phishingScore > 0) { score += phishingScore; signalCount++; }

        // [I] Suspicious path / file extension
        int pathScore = checkSuspiciousPath(parsed, result);
        if (pathScore > 0) { score += pathScore; signalCount++; }

        // [J] Excessive subdomain depth
        int subdomainScore = checkSubdomainDepth(parsed, result, domainInfo);
        if (subdomainScore > 0) { score += subdomainScore; signalCount++; }

        // [K] URL length anomaly
        int lengthScore = checkUrlLength(url, result);
        if (lengthScore > 0) { score += lengthScore; signalCount++; }

        // [L] Obfuscation patterns (@ symbol, double slashes, encoded chars)
        int obfuscScore = checkObfuscation(url, result);
        if (obfuscScore > 0) { score += obfuscScore; signalCount++; }

        // [M] Newly registered domain heuristic (BUG FIX: was missing entirely)
        int newDomainScore = checkNewDomain(parsed, result, domainInfo);
        if (newDomainScore > 0) { score += newDomainScore; signalCount++; }

        // [N] Fake security/scanner website indicators
        int fakeSecScore = checkFakeSecuritySite(url, parsed, result);
        if (fakeSecScore > 0) { score += fakeSecScore; signalCount++; }

        // ══════════════════════════════════════════════
        //  VERDICT DERIVATION  (BUG FIX: was backwards)
        // ══════════════════════════════════════════════
        score = Math.min(score, 100);

        // Trusted-domain whitelist — only reduces score, never overrides blacklist
        if (blacklistScore == 0 && isTrustedDomain(parsed)) {
            score = Math.max(0, score - 20);
            result.getIndicators().add("TRUSTED_DOMAIN_WHITELISTED: Recognized legitimate domain");
        }

        result.setThreatScore(score);

        // Confidence: more independent signals = higher confidence
        int confidence = Math.min(95, 40 + (signalCount * 10));
        if (signalCount == 0) confidence = 60; // baseline uncertainty
        result.setConfidenceScore(confidence);

        // Assign verdict
        String verdict;
        if (score <= SAFE_THRESHOLD) {
            verdict = "SAFE";
            result.setRecommendation("This URL appears safe. Standard caution still advised.");
        } else if (score <= SUSPICIOUS_THRESHOLD) {
            verdict = "SUSPICIOUS";
            result.setRecommendation(
                "Proceed with extreme caution. Verify the source independently before entering any credentials.");
        } else {
            verdict = "MALICIOUS";
            result.setRecommendation(
                "DO NOT visit this URL. It exhibits multiple characteristics of a phishing, malware, or scam site.");
        }
        result.setVerdict(verdict);

        // Populate categories
        populateCategories(result);

        result.setScanDurationMs(System.currentTimeMillis() - start);
        return result;
    }

    // ─────────────────────────────────────────────────────────────────
    //  INDIVIDUAL CHECKS
    // ─────────────────────────────────────────────────────────────────

    /** [A] Blacklist — +50 pts, immediate high confidence */
    private int checkBlacklist(ParsedUrl p, ThreatResult r) {
        String host = p.host.toLowerCase();
        // Check exact domain and all parent domains
        if (BLACKLISTED_DOMAINS.contains(host)) {
            r.getThreats().add("BLACKLISTED: Domain found in known-malicious database");
            r.getIndicators().add("Exact domain match in threat intelligence feed");
            return 50;
        }
        // Check registrable domain (strip subdomains)
        String regDomain = getRegistrableDomain(host);
        if (BLACKLISTED_DOMAINS.contains(regDomain)) {
            r.getThreats().add("BLACKLISTED_PARENT: Parent domain is blacklisted");
            r.getIndicators().add("Parent domain '" + regDomain + "' found in blacklist");
            return 45;
        }
        return 0;
    }

    /** [B] IP address as host — legitimate sites use domains, not raw IPs */
    private int checkIpAddress(ParsedUrl p, ThreatResult r) {
        if (IP_PATTERN.matcher(p.host).matches()) {
            // BUG FIX: previous code checked this but returned 0
            r.getThreats().add("IP_AS_HOST: URL uses raw IP address instead of domain name");
            r.getIndicators().add("Host is IP: " + p.host + " — bypasses domain reputation");
            r.getDomainInfo().setIPAddress(true);

            // Private/reserved IP ranges
            if (p.host.startsWith("192.168.") || p.host.startsWith("10.") || p.host.startsWith("172.")) {
                r.getIndicators().add("PRIVATE_IP: Internal network IP exposed in URL");
                return 35;
            }
            return 40;
        }
        return 0;
    }

    /** [C] Homograph / IDN attack detection */
    private int checkHomograph(ParsedUrl p, ThreatResult r, ThreatResult.DomainInfo d) {
        if (HOMOGRAPH_PATTERN.matcher(p.host).find()) {
            // BUG FIX: this check was entirely absent
            r.getThreats().add("HOMOGRAPH_ATTACK: Non-ASCII characters in domain (IDN homograph)");
            r.getIndicators().add("Detected Unicode lookalike characters in: " + p.host);
            d.setHasHomographChars(true);
            return 45;
        }
        return 0;
    }

    /** [D] Suspicious TLD */
    private int checkSuspiciousTld(ParsedUrl p, ThreatResult r, ThreatResult.DomainInfo d) {
        for (String tld : SUSPICIOUS_TLDS) {
            if (p.host.endsWith(tld)) {
                d.setSuspiciousTld(true);
                d.setTld(tld);
                r.getIndicators().add("SUSPICIOUS_TLD: '" + tld + "' is a free TLD heavily abused in phishing");
                return 20;
            }
        }
        return 0;
    }

    /** [E] Brand impersonation & typosquatting */
    private int checkBrandImpersonation(ParsedUrl p, String fullUrl, ThreatResult r) {
        String urlLower = fullUrl.toLowerCase();
        String hostLower = p.host.toLowerCase();
        int score = 0;

        for (Map.Entry<String, String> entry : BRAND_DOMAINS.entrySet()) {
            String brand = entry.getKey();
            String trustedDomain = entry.getValue();

            boolean urlMentionsBrand = urlLower.contains(brand);
            boolean hostIsLegit = hostLower.equals(trustedDomain)
                || hostLower.endsWith("." + trustedDomain);

            if (urlMentionsBrand && !hostIsLegit) {
                // BUG FIX: typosquatting threshold was ≤ 5, now ≤ 2
                String registrable = getRegistrableDomain(hostLower);
                int editDist = levenshteinDistance(registrable, trustedDomain);

                if (editDist <= 2 && editDist > 0) {
                    r.getThreats().add("TYPOSQUATTING: '" + registrable
                        + "' is 1-2 chars away from '" + trustedDomain + "'");
                    r.getIndicators().add("Edit distance " + editDist + " from brand domain");
                    score += 40;
                } else if (editDist > 2) {
                    r.getThreats().add("BRAND_IMPERSONATION: URL references '" + brand
                        + "' but domain is '" + registrable + "'");
                    r.getIndicators().add("Brand keyword '" + brand + "' used in non-brand domain");
                    score += 30;
                }
            }
        }
        return Math.min(score, 50);
    }

    /** [F] SSL/TLS check — HTTP = risk, absent/expired cert = risk */
    private int checkSsl(ParsedUrl p, ThreatResult.SslInfo ssl, ThreatResult r) {
        // BUG FIX: previous code was flagging HTTPS as suspicious
        if ("http".equalsIgnoreCase(p.scheme)) {
            r.getIndicators().add("NO_SSL: Site uses unencrypted HTTP");
            ssl.setHasSSL(false);
            ssl.setValid(false);
            return 15;
        }
        // HTTPS is expected — no positive score for it, just neutral
        ssl.setHasSSL(true);
        ssl.setIssuer("Certificate authority (simulated)");
        ssl.setValid(true);
        return 0;
    }

    /** [G] URL shortener — never safe without redirect resolution */
    private int checkUrlShortener(ParsedUrl p, ThreatResult r) {
        // BUG FIX: shorteners were returned as SAFE
        if (URL_SHORTENERS.contains(p.host.toLowerCase())) {
            r.getIndicators().add("URL_SHORTENER: Short URL hides the real destination");
            r.getThreats().add("MASKED_DESTINATION: URL shortener conceals final URL — cannot verify safety");
            return 25;
        }
        return 0;
    }

    /** [H] Phishing keywords in the URL */
    private int checkPhishingKeywords(String url, ParsedUrl p, ThreatResult r) {
        // BUG FIX: was matching keywords but adding 0 to score
        String urlLower = url.toLowerCase();
        int hits = 0;
        List<String> matched = new ArrayList<>();

        for (String kw : PHISHING_KEYWORDS) {
            if (urlLower.contains(kw)) {
                matched.add(kw);
                hits++;
            }
        }

        if (hits == 0) return 0;

        // Weight: 1 keyword = minor, 2+ = notable, 4+ = strong phishing signal
        int score = 0;
        if (hits == 1) score = 10;
        else if (hits == 2) score = 20;
        else if (hits == 3) score = 28;
        else score = Math.min(35, hits * 8);

        r.getIndicators().add("PHISHING_KEYWORDS (" + hits + "): "
            + String.join(", ", matched.subList(0, Math.min(5, matched.size()))));
        if (hits >= 3) {
            r.getThreats().add("HIGH_KEYWORD_DENSITY: Multiple phishing terms in URL path");
        }
        return score;
    }

    /** [I] Suspicious path / malicious file extension */
    private int checkSuspiciousPath(ParsedUrl p, ThreatResult r) {
        String path = p.path != null ? p.path.toLowerCase() : "";
        for (Pattern pat : SUSPICIOUS_PATH_PATTERNS) {
            Matcher m = pat.matcher(path);
            if (m.find()) {
                r.getThreats().add("SUSPICIOUS_PATH: Path matches pattern: " + pat.pattern());
                r.getIndicators().add("Dangerous path segment detected: " + m.group());
                return 30;
            }
        }
        return 0;
    }

    /** [J] Excessive subdomain depth — phishing kits often use many subdomains */
    private int checkSubdomainDepth(ParsedUrl p, ThreatResult r, ThreatResult.DomainInfo d) {
        String[] parts = p.host.split("\\.");
        int depth = parts.length - 2;  // subtract SLD + TLD
        d.setSubdomainDepth(Math.max(0, depth));

        if (depth >= 4) {
            r.getIndicators().add("DEEP_SUBDOMAIN: " + depth + " subdomain levels — unusual for legitimate sites");
            r.getThreats().add("SUBDOMAIN_ABUSE: Excessive subdomains to obscure real domain");
            return 25;
        } else if (depth == 3) {
            r.getIndicators().add("ELEVATED_SUBDOMAIN: 3 subdomain levels");
            return 10;
        }
        return 0;
    }

    /** [K] URL length — very long URLs are often obfuscation */
    private int checkUrlLength(String url, ThreatResult r) {
        int len = url.length();
        if (len > 200) {
            r.getIndicators().add("VERY_LONG_URL: " + len + " chars — likely obfuscated");
            return 20;
        } else if (len > 100) {
            r.getIndicators().add("LONG_URL: " + len + " chars");
            return 8;
        }
        return 0;
    }

    /** [L] Obfuscation: @ in URL, double-slash tricks, excessive encoding */
    private int checkObfuscation(String url, ThreatResult r) {
        int score = 0;
        if (url.contains("@")) {
            r.getThreats().add("AT_SYMBOL_OBFUSCATION: '@' in URL redirects browser to post-@ host");
            r.getIndicators().add("'@' symbol used — everything before '@' is ignored by browser");
            score += 35;
        }
        if (url.matches(".*https?://[^/]+/.*https?://.*")) {
            r.getThreats().add("DOUBLE_URL: URL contains embedded second URL (open redirect abuse)");
            score += 30;
        }
        // Count percent-encoded characters
        long encodedCount = url.chars().filter(c -> c == '%').count();
        if (encodedCount > 5) {
            r.getIndicators().add("HEAVY_ENCODING: " + encodedCount + " percent-encoded chars (obfuscation)");
            score += 15;
        }
        return Math.min(score, 40);
    }

    /** [M] Newly registered domain heuristic (BUG FIX: was entirely missing) */
    private int checkNewDomain(ParsedUrl p, ThreatResult r, ThreatResult.DomainInfo d) {
        String host = p.host.toLowerCase();

        // Heuristic: suspicious TLD + phishing keyword in domain = likely new
        boolean hasSuspiciousTld = SUSPICIOUS_TLDS.stream().anyMatch(host::endsWith);
        boolean hasPhishingKwInDomain = PHISHING_KEYWORDS.stream()
            .anyMatch(kw -> getRegistrableDomain(host).contains(kw));
        boolean knownBrandAbuse = BRAND_DOMAINS.keySet().stream()
            .anyMatch(brand -> host.contains(brand)
                && !host.equals(BRAND_DOMAINS.get(brand))
                && !host.endsWith("." + BRAND_DOMAINS.get(brand)));

        if (hasSuspiciousTld && (hasPhishingKwInDomain || knownBrandAbuse)) {
            d.setNewDomain(true);
            d.setDomainAge(0);
            r.getIndicators().add("LIKELY_NEW_DOMAIN: Free TLD + phishing keyword — pattern matches newly registered phishing domains");
            r.getThreats().add("NEW_PHISHING_DOMAIN: Domain exhibits hallmarks of a freshly registered phishing site");
            return 20;
        }
        return 0;
    }

    /** [N] Fake antivirus / fake security scanner sites */
    private int checkFakeSecuritySite(String url, ParsedUrl p, ThreatResult r) {
        String urlLower = url.toLowerCase();
        List<String> fakeSecKeywords = Arrays.asList(
            "your-pc-is-infected", "virus-detected", "scan-now", "remove-virus",
            "computer-infected", "malware-found", "security-alert", "system-warning",
            "free-scan", "antivirus-download", "protect-now", "click-to-clean"
        );

        for (String kw : fakeSecKeywords) {
            if (urlLower.contains(kw)) {
                r.getThreats().add("FAKE_SECURITY_SITE: URL contains fake AV / scareware keyword: '" + kw + "'");
                r.getIndicators().add("Scareware pattern detected — designed to trick users into installing malware");
                return 40;
            }
        }
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────
    //  HELPER METHODS
    // ─────────────────────────────────────────────────────────────────

    private String normalizeUrl(String url) {
        url = url.trim();
        if (!url.contains("://")) {
            url = "http://" + url; // assume HTTP for bare domains
        }
        return url;
    }

    private ParsedUrl parseUrl(String url) throws URISyntaxException {
        URI uri = new URI(url);
        ParsedUrl p = new ParsedUrl();
        p.scheme = uri.getScheme() != null ? uri.getScheme() : "http";
        p.host   = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
        p.path   = uri.getPath() != null ? uri.getPath() : "";
        p.query  = uri.getQuery() != null ? uri.getQuery() : "";
        p.full   = url;
        if (p.host.isEmpty()) {
            throw new URISyntaxException(url, "Empty host");
        }
        return p;
    }

    private ThreatResult.DomainInfo buildDomainInfo(ParsedUrl p) {
        ThreatResult.DomainInfo d = new ThreatResult.DomainInfo();
        d.setDomain(p.host);
        d.setDomainAge(-1);
        d.setNewDomain(false);
        d.setIPAddress(false);
        d.setSubdomainDepth(0);
        d.setHasHomographChars(false);
        d.setTld(extractTld(p.host));
        d.setSuspiciousTld(false);
        return d;
    }

    private ThreatResult.SslInfo buildSslInfo(ParsedUrl p, String url) {
        ThreatResult.SslInfo ssl = new ThreatResult.SslInfo();
        ssl.setHasSSL("https".equalsIgnoreCase(p.scheme));
        ssl.setValid(ssl.isHasSSL()); // simulated
        ssl.setIssuer(ssl.isHasSSL() ? "Let's Encrypt / CA (simulated)" : "None");
        ssl.setSelfSigned(false);
        ssl.setMismatchedDomain(false);
        return ssl;
    }

    private boolean isTrustedDomain(ParsedUrl p) {
        String registrable = getRegistrableDomain(p.host.toLowerCase());
        return TRUSTED_DOMAINS.contains(registrable);
    }

    private String getRegistrableDomain(String host) {
        String[] parts = host.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }

    private String extractTld(String host) {
        int dot = host.lastIndexOf('.');
        return dot >= 0 ? host.substring(dot) : "";
    }

    /** Levenshtein distance — used for typosquatting detection */
    private int levenshteinDistance(String a, String b) {
        int m = a.length(), n = b.length();
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 0; i <= m; i++) dp[i][0] = i;
        for (int j = 0; j <= n; j++) dp[0][j] = j;
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                int cost = a.charAt(i-1) == b.charAt(j-1) ? 0 : 1;
                dp[i][j] = Math.min(dp[i-1][j] + 1,
                            Math.min(dp[i][j-1] + 1,
                                     dp[i-1][j-1] + cost));
            }
        }
        return dp[m][n];
    }

    private void populateCategories(ThreatResult r) {
        List<String> threats = r.getThreats();
        for (String t : threats) {
            if (t.contains("PHISH") || t.contains("BRAND") || t.contains("TYPO"))
                addCategory(r, "Phishing");
            if (t.contains("MALWARE") || t.contains("BLACKLIST"))
                addCategory(r, "Malware");
            if (t.contains("FAKE_SECURITY") || t.contains("SCAREWARE"))
                addCategory(r, "Scareware / Fake AV");
            if (t.contains("SHORTENER") || t.contains("MASKED"))
                addCategory(r, "Masked URL");
            if (t.contains("OBFUS") || t.contains("ENCODING") || t.contains("AT_SYMBOL"))
                addCategory(r, "URL Obfuscation");
            if (t.contains("IP_AS_HOST") || t.contains("HOMOGRAPH"))
                addCategory(r, "Domain Spoofing");
            if (t.contains("NEW_PHISHING") || t.contains("NEW_DOMAIN"))
                addCategory(r, "Newly Registered Domain");
        }
        if (r.getCategories().isEmpty() && "SAFE".equals(r.getVerdict())) {
            r.getCategories().add("Clean");
        }
    }

    private void addCategory(ThreatResult r, String cat) {
        if (!r.getCategories().contains(cat)) r.getCategories().add(cat);
    }

    // ─────────────────────────────────────────────────────────────────
    //  INNER DTO
    // ─────────────────────────────────────────────────────────────────
    private static class ParsedUrl {
        String scheme, host, path, query, full;
    }
}
