package com.qrscanner.service;

import com.qrscanner.model.ThreatResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class QrService {

    @Autowired
    private UrlDetectionService detectionService;

    /**
     * Simulates decoding a QR code and analyzing its payload.
     * In production this would use a real QR library (ZXing / zbar).
     */
    public Map<String, Object> scanQrCode(String qrData) {
        Map<String, Object> response = new LinkedHashMap<>();

        // Determine payload type
        String payloadType = detectPayloadType(qrData);
        response.put("payloadType", payloadType);
        response.put("rawPayload", qrData);

        if ("URL".equals(payloadType)) {
            ThreatResult analysis = detectionService.analyze(qrData);
            response.put("analysis", analysis);
            response.put("isUrl", true);
        } else if ("TEXT".equals(payloadType)) {
            // Check if text contains embedded URL
            String extractedUrl = extractUrlFromText(qrData);
            if (extractedUrl != null) {
                ThreatResult analysis = detectionService.analyze(extractedUrl);
                response.put("analysis", analysis);
                response.put("isUrl", true);
                response.put("extractedUrl", extractedUrl);
            } else {
                response.put("isUrl", false);
                response.put("message", "QR code contains plain text — no URL to analyze.");
            }
        } else {
            response.put("isUrl", false);
            response.put("message", "QR code payload type: " + payloadType);
        }

        return response;
    }

    public ThreatResult analyzeUrl(String url) {
        return detectionService.analyze(url);
    }

    // ── helpers ──

    private String detectPayloadType(String data) {
        if (data == null || data.isBlank()) return "EMPTY";
        String d = data.trim().toLowerCase();
        if (d.startsWith("http://") || d.startsWith("https://") || d.startsWith("www.")) return "URL";
        if (d.startsWith("mailto:")) return "EMAIL";
        if (d.startsWith("tel:"))    return "PHONE";
        if (d.startsWith("smsto:"))  return "SMS";
        if (d.startsWith("wifi:"))   return "WIFI";
        if (d.startsWith("geo:"))    return "LOCATION";
        return "TEXT";
    }

    private String extractUrlFromText(String text) {
        java.util.regex.Pattern urlPat = java.util.regex.Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher m = urlPat.matcher(text);
        return m.find() ? m.group() : null;
    }
}
