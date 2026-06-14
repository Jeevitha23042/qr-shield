package com.qrscanner.controller;

import com.qrscanner.model.ThreatResult;
import com.qrscanner.service.QrService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class ScannerController {

    @Autowired
    private QrService qrService;

    /**
     * POST /api/scan/url
     * Body: { "url": "https://..." }
     */
    @PostMapping("/scan/url")
    public ResponseEntity<ThreatResult> scanUrl(@RequestBody Map<String, String> body) {
        String url = body.getOrDefault("url", "").trim();
        if (url.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        ThreatResult result = qrService.analyzeUrl(url);
        return ResponseEntity.ok(result);
    }

    /**
     * POST /api/scan/qr
     * Body: { "data": "<qr payload>" }
     */
    @PostMapping("/scan/qr")
    public ResponseEntity<Map<String, Object>> scanQr(@RequestBody Map<String, String> body) {
        String data = body.getOrDefault("data", "").trim();
        if (data.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }
        Map<String, Object> result = qrService.scanQrCode(data);
        return ResponseEntity.ok(result);
    }

    /**
     * GET /api/health
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "service", "QR Scanner & URL Threat Detection",
            "version", "2.0.0-fixed"
        ));
    }

    /**
     * GET /api/test-cases — returns pre-built test URLs for demo
     */
    @GetMapping("/test-cases")
    public ResponseEntity<List<Map<String, String>>> testCases() {
        List<Map<String, String>> cases = new ArrayList<>();
        addCase(cases, "https://www.google.com",                          "Legitimate",  "Google Homepage");
        addCase(cases, "https://github.com/torvalds/linux",               "Legitimate",  "GitHub Repo");
        addCase(cases, "http://secure-paypal-login.tk/verify",            "Malicious",   "PayPal Phishing");
        addCase(cases, "http://paypa1.com/signin/account-verify",         "Malicious",   "Typosquatting PayPal");
        addCase(cases, "http://192.168.1.1/admin/login.php",              "Suspicious",  "IP-based Admin Login");
        addCase(cases, "http://amazon-account-suspended.xyz/unlock",      "Malicious",   "Amazon Phishing");
        addCase(cases, "https://bit.ly/3xR7qT2",                          "Suspicious",  "URL Shortener");
        addCase(cases, "http://apple-id-suspended.ml/verify-account",     "Malicious",   "Apple ID Phishing");
        addCase(cases, "https://your-pc-is-infected-scan-now.com/remove", "Malicious",   "Fake AV Scareware");
        addCase(cases, "https://login.microsofт.com/secure",              "Malicious",   "Homograph Attack");
        addCase(cases, "https://bankofamerica-verify.xyz/login/confirm",  "Malicious",   "Bank Phishing");
        addCase(cases, "https://www.amazon.com/dp/B09G9FPHY6",            "Legitimate",  "Amazon Product");
        return ResponseEntity.ok(cases);
    }

    private void addCase(List<Map<String, String>> list, String url, String expected, String label) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("url", url);
        m.put("expectedVerdict", expected);
        m.put("label", label);
        list.add(m);
    }
}
