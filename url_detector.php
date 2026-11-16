
<?php

require_once "db.php";

// ==========================================
// PHISHGUARD ADVANCED URL DETECTION ENGINE
// ==========================================

// Add your Google Safe Browsing API key here.
// Leave empty to use local detection only.
$googleSafeBrowsingApiKey = "";


function checkGoogleSafeBrowsing($url, $apiKey)
{
    if (empty($apiKey) || !function_exists('curl_init')) {
        return null;
    }

    $apiUrl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
        . urlencode($apiKey);

    $data = [
        "client" => [
            "clientId" => "phishguard",
            "clientVersion" => "1.0"
        ],
        "threatInfo" => [
            "threatTypes" => [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes" => ["ANY_PLATFORM"],
            "threatEntryTypes" => ["URL"],
            "threatEntries" => [
                ["url" => $url]
            ]
        ]
    ];

    $ch = curl_init($apiUrl);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => [
            "Content-Type: application/json"
        ],
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_TIMEOUT => 10
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    curl_close($ch);

    if ($response === false || $httpCode !== 200) {
        return null;
    }

    $result = json_decode($response, true);

    return !empty($result['matches']);
}


// ==========================================
// URL ANALYSIS FUNCTION
// ==========================================


// ==========================================
// BRAND IMPERSONATION DETECTION
// ==========================================

function detectBrandImpersonation($host)
{
    $brands = [
        "paypal" => "paypal.com",
        "google" => "google.com",
        "amazon" => "amazon.com",
        "microsoft" => "microsoft.com",
        "apple" => "apple.com",
        "hdfc" => "hdfcbank.com",
        "icici" => "icicibank.com",
        "sbi" => "onlinesbi.sbi"
    ];

    $host = strtolower($host);

    // Remove www prefix
    $host = preg_replace('/^www\./', '', $host);

    $hostParts = explode(".", $host);

    // Ignore known legitimate brand domains and their subdomains
    foreach ($brands as $brand => $officialDomain) {
        if (
            $host === $officialDomain ||
            substr($host, -strlen("." . $officialDomain)) === "." . $officialDomain
        ) {
            return [];
        }
    }

    // Normalize common character substitutions
    $normalize = function ($value) {
        return strtr(strtolower($value), [
            "0" => "o",
            "1" => "l",
            "3" => "e",
            "5" => "s"
        ]);
    };

    $detectedBrands = [];

    foreach ($hostParts as $part) {

        // Split domain labels such as paypal-login
        $tokens = preg_split('/[-_]/', $part);

        foreach ($tokens as $token) {

            $normalizedToken = $normalize($token);

            foreach ($brands as $brand => $officialDomain) {

                // Exact brand match in a non-official domain
                if ($normalizedToken === $brand) {
                    $detectedBrands[] = $brand;
                    continue;
                }

                // Check for small spelling differences
                if (
                    strlen($brand) >= 5 &&
                    levenshtein($normalizedToken, $brand) <= 1
                ) {
                    $detectedBrands[] = $brand;
                }
            }
        }
    }

    return array_values(array_unique($detectedBrands));
}

function analyzeURL($url, $apiKey)
{
    $score = 0;
    $reasons = [];

    $parsed = parse_url($url);

    if (!$parsed || empty($parsed['host'])) {
        return [
            "score" => 0,
            "level" => "INVALID",
            "reasons" => ["Invalid URL format."]
        ];
    }

    $host = strtolower($parsed['host']);
    $path = strtolower($parsed['path'] ?? '');
    $query = strtolower($parsed['query'] ?? '');

    $fullURL = strtolower($url);

    // --------------------------------------
    // 1. Suspicious keywords
    // --------------------------------------

    $keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "signin",
        "banking",
        "password",
        "confirm",
        "wallet",
        "payment"
    ];

    $keywordFound = [];

    foreach ($keywords as $keyword) {
        if (preg_match(
            '/(^|[^a-z0-9])' . preg_quote($keyword, '/') . '([^a-z0-9]|$)/i',
            $fullURL
        )) {
            $keywordFound[] = $keyword;
        }
    }

    if (!empty($keywordFound)) {
        $score += min(count($keywordFound) * 10, 30);

        $reasons[] = "Suspicious keywords found: "
            . implode(", ", $keywordFound);
    }


    // --------------------------------------
    // 2. IP address instead of domain
    // --------------------------------------

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $score += 40;
        $reasons[] = "URL uses an IP address instead of a domain name.";
    }


    // --------------------------------------
    // 3. Multiple hyphens
    // --------------------------------------

    if (substr_count($host, "-") >= 2) {
        $score += 15;
        $reasons[] = "Domain contains multiple hyphens.";
    }


    // --------------------------------------
    // 4. Long URL
    // --------------------------------------

    if (strlen($url) > 100) {
        $score += 15;
        $reasons[] = "URL is unusually long.";
    }


    // --------------------------------------
    // 5. Suspicious top-level domains
    // --------------------------------------

    $suspiciousTlds = [
        "xyz",
        "top",
        "click",
        "work",
        "live",
        "zip",
        "mov"
    ];

    $extension = strtolower(pathinfo($host, PATHINFO_EXTENSION));

    if (in_array($extension, $suspiciousTlds, true)) {
        $score += 20;
        $reasons[] = "Domain uses a commonly abused TLD: ." . $extension;
    }


    // --------------------------------------
    // 6. Multiple subdomains
    // --------------------------------------

    if (!filter_var($host, FILTER_VALIDATE_IP)) {

        $domainParts = explode(".", $host);

        if (count($domainParts) >= 5) {
            $score += 20;
            $reasons[] = "Domain contains an unusually large number of subdomains.";
        }
    }


    // --------------------------------------
    // 7. @ symbol detection
    // --------------------------------------

    if (strpos($url, "@") !== false) {
        $score += 25;
        $reasons[] = "URL contains an @ symbol that may disguise its destination.";
    }


    // --------------------------------------
    // 8. URL shortener detection
    // --------------------------------------

    $shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rebrand.ly"
    ];

    if (in_array($host, $shorteners, true)) {
        $score += 15;
        $reasons[] = "URL uses a shortening service that hides the final destination.";
    }


    // --------------------------------------
    // 9. Punycode detection
    // --------------------------------------

    if (strpos($host, "xn--") !== false) {
        $score += 25;
        $reasons[] = "Punycode domain detected; check for possible character impersonation.";
    }

// --------------------------------------
// 9A. Brand impersonation detection
// --------------------------------------

$brandMatches = detectBrandImpersonation($host);

if (!empty($brandMatches)) {

    $score += 30;

    $reasons[] = "Possible brand impersonation detected: "
        . implode(", ", $brandMatches);

    $reasons[] = "The domain resembles a known brand but does not use its official domain.";
}


    // --------------------------------------
    // 10. HTTPS information
    // --------------------------------------

    $scheme = strtolower($parsed['scheme'] ?? '');

    if ($scheme !== "https") {
        $reasons[] = "HTTPS is not used. The connection may lack encryption.";
    } else {
        $reasons[] = "HTTPS is present. This does not guarantee that the website is legitimate.";
    }


    // --------------------------------------
    // 11. Google Safe Browsing check
    // --------------------------------------

    $reputation = checkGoogleSafeBrowsing($url, $apiKey);

    if ($reputation === true) {
        $score += 100;
        $reasons[] = "Google Safe Browsing reports this URL as unsafe.";
    } elseif ($reputation === false) {
        $reasons[] = "Google Safe Browsing returned no known threat match.";
    } else {
        $reasons[] = "External reputation check unavailable; local analysis was used.";
    }


    // --------------------------------------
    // 12. Final risk classification
    // --------------------------------------

    $score = min($score, 100);

    if ($score <= 20) {
        $level = "LOW";
    } elseif ($score <= 50) {
        $level = "MEDIUM";
    } else {
        $level = "HIGH";
    }

    return [
        "score" => $score,
        "level" => $level,
        "reasons" => $reasons
    ];
}


// ==========================================
// FORM PROCESSING
// ==========================================

$result = null;
$submittedURL = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $submittedURL = trim($_POST['url'] ?? '');

    // Validate URL
    if (
        !filter_var($submittedURL, FILTER_VALIDATE_URL) ||
        !in_array(
            strtolower(parse_url($submittedURL, PHP_URL_SCHEME) ?? ''),
            ["http", "https"],
            true
        )
    ) {

        $error = "Please enter a valid HTTP or HTTPS URL.";

    } else {

        $result = analyzeURL(
            $submittedURL,
            $googleSafeBrowsingApiKey
        );

        // Save scan result in database
        if ($result['level'] !== "INVALID") {

            $stmt = $conn->prepare(
                "INSERT INTO url_scans
                (url, risk_score, risk_level)
                VALUES (?, ?, ?)"
            );

            $stmt->bind_param(
                "sis",
                $submittedURL,
                $result['score'],
                $result['level']
            );

            $stmt->execute();
            $stmt->close();
        }
    }
}

?>


<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PhishGuard - Advanced URL Detector</title>

    <link rel="stylesheet" href="style.css?v=16">

    <style>

        .detection-result {
            margin-top: 25px;
            padding: 20px;
            border-radius: 12px;
            background: #f4f7fb;
        }

        .risk-score {
            font-size: 32px;
            font-weight: bold;
            margin: 12px 0;
        }

        .risk-low {
            color: #16834b;
        }

        .risk-medium {
            color: #b8860b;
        }

        .risk-high {
            color: #d93025;
        }

        .detection-list {
            padding-left: 20px;
            line-height: 1.8;
        }

        .detection-error {
            color: #d93025;
            margin-top: 15px;
        }

    </style>

</head>


<body>

    <div class="login-box">

        <h2>PhishGuard URL Detector</h2>

        <p>
            Analyze suspicious URLs and identify possible phishing characteristics.
        </p>

        <form method="POST">

            <label for="url">Enter URL to Scan</label>

            <input
                type="url"
                id="url"
                name="url"
                placeholder="https://example.com"
                value="<?php echo htmlspecialchars($submittedURL); ?>"
                required
            >

            <button type="submit">
                Scan URL
            </button>

        </form>


        <?php if (isset($error)): ?>

            <div class="detection-error">
                <?php echo htmlspecialchars($error); ?>
            </div>

        <?php endif; ?>


        <?php if ($result !== null): ?>

            <div class="detection-result">

                <h3>URL Analysis Result</h3>

                <p>
                    <strong>Scanned URL:</strong><br>

                    <?php echo htmlspecialchars($submittedURL); ?>
                </p>

                <div class="risk-score
                    <?php
                    echo $result['level'] === "HIGH"
                        ? "risk-high"
                        : ($result['level'] === "MEDIUM"
                            ? "risk-medium"
                            : "risk-low");
                    ?>">

                    <?php echo $result['score']; ?>/100

                </div>

                <h3>
                    Risk Level:
                    <?php echo htmlspecialchars($result['level']); ?>
                </h3>

                <h4>Detection Findings</h4>

                <ul class="detection-list">

                    <?php foreach ($result['reasons'] as $reason): ?>

                        <li>
                            <?php echo htmlspecialchars($reason); ?>
                        </li>

                    <?php endforeach; ?>

                </ul>

                <p>
                    <strong>Recommendation:</strong>

                    Do not enter personal or financial information
                    on a suspicious website until its identity
                    has been independently verified.
                </p>

            </div>

        <?php endif; ?>


        <br>

        <a href="awareness.php">Back to Awareness Dashboard</a>

    </div>

</body>

</html>
