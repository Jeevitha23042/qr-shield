package com.qrscanner.model;

import java.util.List;
import java.util.ArrayList;

public class ThreatResult {
    private String url;
    private String verdict;           // SAFE, SUSPICIOUS, MALICIOUS
    private int threatScore;          // 0-100
    private int confidenceScore;      // 0-100
    private List<String> threats;
    private List<String> indicators;
    private DomainInfo domainInfo;
    private SslInfo sslInfo;
    private List<String> categories;
    private String recommendation;
    private long scanDurationMs;

    public ThreatResult() {
        this.threats = new ArrayList<>();
        this.indicators = new ArrayList<>();
        this.categories = new ArrayList<>();
    }

    // --- Getters & Setters ---
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getVerdict() { return verdict; }
    public void setVerdict(String verdict) { this.verdict = verdict; }

    public int getThreatScore() { return threatScore; }
    public void setThreatScore(int threatScore) { this.threatScore = threatScore; }

    public int getConfidenceScore() { return confidenceScore; }
    public void setConfidenceScore(int confidenceScore) { this.confidenceScore = confidenceScore; }

    public List<String> getThreats() { return threats; }
    public void setThreats(List<String> threats) { this.threats = threats; }

    public List<String> getIndicators() { return indicators; }
    public void setIndicators(List<String> indicators) { this.indicators = indicators; }

    public DomainInfo getDomainInfo() { return domainInfo; }
    public void setDomainInfo(DomainInfo domainInfo) { this.domainInfo = domainInfo; }

    public SslInfo getSslInfo() { return sslInfo; }
    public void setSslInfo(SslInfo sslInfo) { this.sslInfo = sslInfo; }

    public List<String> getCategories() { return categories; }
    public void setCategories(List<String> categories) { this.categories = categories; }

    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }

    public long getScanDurationMs() { return scanDurationMs; }
    public void setScanDurationMs(long scanDurationMs) { this.scanDurationMs = scanDurationMs; }

    public static class DomainInfo {
        private String domain;
        private int domainAge;          // days, -1 = unknown
        private boolean isNewDomain;
        private boolean isIPAddress;
        private int subdomainDepth;
        private boolean hasHomographChars;
        private String tld;
        private boolean isSuspiciousTld;

        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        public int getDomainAge() { return domainAge; }
        public void setDomainAge(int domainAge) { this.domainAge = domainAge; }
        public boolean isNewDomain() { return isNewDomain; }
        public void setNewDomain(boolean newDomain) { isNewDomain = newDomain; }
        public boolean isIPAddress() { return isIPAddress; }
        public void setIPAddress(boolean IPAddress) { isIPAddress = IPAddress; }
        public int getSubdomainDepth() { return subdomainDepth; }
        public void setSubdomainDepth(int subdomainDepth) { this.subdomainDepth = subdomainDepth; }
        public boolean isHasHomographChars() { return hasHomographChars; }
        public void setHasHomographChars(boolean hasHomographChars) { this.hasHomographChars = hasHomographChars; }
        public String getTld() { return tld; }
        public void setTld(String tld) { this.tld = tld; }
        public boolean isSuspiciousTld() { return isSuspiciousTld; }
        public void setSuspiciousTld(boolean suspiciousTld) { isSuspiciousTld = suspiciousTld; }
    }

    public static class SslInfo {
        private boolean hasSSL;
        private boolean isValid;
        private String issuer;
        private String expiryDate;
        private boolean isSelfSigned;
        private boolean mismatchedDomain;

        public boolean isHasSSL() { return hasSSL; }
        public void setHasSSL(boolean hasSSL) { this.hasSSL = hasSSL; }
        public boolean isValid() { return isValid; }
        public void setValid(boolean valid) { isValid = valid; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getExpiryDate() { return expiryDate; }
        public void setExpiryDate(String expiryDate) { this.expiryDate = expiryDate; }
        public boolean isSelfSigned() { return isSelfSigned; }
        public void setSelfSigned(boolean selfSigned) { isSelfSigned = selfSigned; }
        public boolean isMismatchedDomain() { return mismatchedDomain; }
        public void setMismatchedDomain(boolean mismatchedDomain) { this.mismatchedDomain = mismatchedDomain; }
    }
}
