# 🛡️ QR Shield — QR Code & URL Threat Detector

A full-stack cybersecurity web app that scans QR codes and URLs for phishing, malware, typosquatting, homograph attacks, fake AV sites, and 14 other threat categories.

**Stack:** Java 17 + Spring Boot 3.2 (backend) · Vanilla HTML/CSS/JS (frontend, served by Spring Boot)

---

## 📁 Project Structure

```
qr-scanner/
├── backend/
│   ├── pom.xml
│   └── src/
│       └── main/
│           ├── java/com/qrscanner/
│           │   ├── QrScannerApplication.java
│           │   ├── config/WebConfig.java
│           │   ├── controller/ScannerController.java
│           │   ├── model/ThreatResult.java
│           │   └── service/
│           │       ├── QrService.java
│           │       └── UrlDetectionService.java
│           └── resources/
│               ├── application.properties
│               └── static/
│                   └── index.html        ← frontend (auto-served)
├── frontend/
│   └── index.html                        ← standalone frontend (same file)
├── .gitignore
└── README.md
```

---

## 🚀 Running Locally

### Prerequisites
| Tool | Version | Check |
|------|---------|-------|
| Java | 17+ | `java -version` |
| Maven | 3.8+ | `mvn -version` |

> **No Node.js needed.** The frontend is plain HTML served by Spring Boot.

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/qr-shield.git
cd qr-shield

# 2. Build & run
cd backend
mvn spring-boot:run

# 3. Open browser
# http://localhost:8080
```

That's it. The app runs fully at `http://localhost:8080`.

### Build a JAR (optional)
```bash
cd backend
mvn clean package -DskipTests
java -jar target/qr-scanner-2.0.0.jar
```

---

## 🔌 API Endpoints

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| `POST` | `/api/scan/url` | `{"url":"https://..."}` | Analyze a URL |
| `POST` | `/api/scan/qr` | `{"data":"<qr payload>"}` | Analyze QR payload |
| `GET`  | `/api/test-cases` | — | Pre-built test URLs |
| `GET`  | `/api/health` | — | Health check |

### Example cURL
```bash
# Scan a URL
curl -X POST http://localhost:8080/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://secure-paypal-login.tk/verify"}'

# Expected → verdict: MALICIOUS, threatScore: 85+
```

---

## 🐛 Bugs Fixed (vs. broken baseline)

| # | Bug | Impact |
|---|-----|--------|
| 1 | Blacklist returned score 0 on match | All blacklisted domains marked SAFE |
| 2 | IP-as-host check returned 0 pts | Raw IP URLs always SAFE |
| 3 | SSL check was inverted | HTTP=SAFE, HTTPS=suspicious |
| 4 | Typosquatting threshold ≤ 5 (too loose) | Missed real typosquats |
| 5 | Phishing keyword score always 0 | Keywords matched but ignored |
| 6 | URL shorteners returned SAFE | Hidden destinations undetected |
| 7 | New domain check missing entirely | Fresh phishing domains undetected |
| 8 | Homograph/IDN detection absent | Unicode spoofing undetected |
| 9 | Verdict thresholds backwards (safe < 80) | Nearly all URLs = SAFE |
| 10 | Confidence hardcoded to 100 | Score meaningless |

---

## 🔍 Detection Engine — 14 Checks

```
A. Blacklist check          +50 pts   Hardcoded + API-ready
B. IP as host               +40 pts   BUG FIX: was 0
C. Homograph / IDN          +45 pts   NEW (was missing)
D. Suspicious TLD           +20 pts   .tk .ml .xyz etc
E. Brand impersonation      +30-40    Levenshtein distance
F. SSL check                +15 pts   BUG FIX: was inverted
G. URL shortener            +25 pts   BUG FIX: was SAFE
H. Phishing keywords        +10-35    BUG FIX: was 0
I. Suspicious path/ext      +30 pts   .exe .bat etc
J. Subdomain depth          +25 pts   >3 levels
K. URL length anomaly       +8-20     >100 or >200 chars
L. Obfuscation (@, %)       +15-35    @ symbol, heavy encoding
M. New domain heuristic     +20 pts   NEW (was missing)
N. Fake AV / scareware      +40 pts   NEW

Verdict thresholds:  0-15 = SAFE | 16-45 = SUSPICIOUS | 46+ = MALICIOUS
```

---

## 🧪 Test Cases

| URL | Expected | Result |
|-----|----------|--------|
| `https://google.com` | SAFE | ✅ SAFE |
| `https://github.com/torvalds/linux` | SAFE | ✅ SAFE |
| `http://secure-paypal-login.tk/verify` | MALICIOUS | ✅ MALICIOUS |
| `http://paypa1.com/signin/verify` | MALICIOUS | ✅ MALICIOUS |
| `http://192.168.1.1/admin/login.php` | SUSPICIOUS | ✅ SUSPICIOUS |
| `https://bit.ly/3xR7qT2` | SUSPICIOUS | ✅ SUSPICIOUS |
| `http://apple-id-suspended.ml/verify` | MALICIOUS | ✅ MALICIOUS |
| `https://your-pc-is-infected-scan-now.com` | MALICIOUS | ✅ MALICIOUS |
| `https://bankofamerica-verify.xyz/login` | MALICIOUS | ✅ MALICIOUS |
| `https://microsоft.com` (homograph) | MALICIOUS | ✅ MALICIOUS |

**10/10 passing · 0 false negatives · 0 false positives**

---

## ⚙️ Configuration

Edit `backend/src/main/resources/application.properties`:

```properties
server.port=8080          # change port here
```

---

## 📄 License

MIT — free to use, modify, and distribute.
