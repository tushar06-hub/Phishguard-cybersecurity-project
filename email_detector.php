
<?php

include("db.php");

$riskScore = 0;
$riskLevel = "";
$reasons = [];
$emailText = "";
$dbError = "";

// ==========================================
// PHISHGUARD EMAIL DETECTION ENGINE
// ==========================================


// Known brands and their official domains
function getTrustedBrands()
{
    return [
        "paypal" => ["paypal.com"],
        "google" => ["google.com"],
        "amazon" => ["amazon.com"],
        "microsoft" => ["microsoft.com"],
        "apple" => ["apple.com"],
        "hdfc" => ["hdfcbank.com"],
        "icici" => ["icicibank.com"],
        "sbi" => ["sbi.co.in", "onlinesbi.sbi"]
    ];
}


// Check whether a domain is an official brand domain
function isOfficialBrandDomain($domain, $officialDomains)
{
    foreach ($officialDomains as $official) {

        if (
            $domain === $official ||
            substr($domain, -strlen("." . $official)) === "." . $official
        ) {
            return true;
        }
    }

    return false;
}


// ==========================================
// MAIN EMAIL ANALYSIS FUNCTION
// ==========================================

function analyzeEmail($emailText)
{
    $score = 0;
    $reasons = [];

    $text = strtolower($emailText);

    $brands = getTrustedBrands();


    // --------------------------------------
    // 1. Suspicious keywords and phrases
    // --------------------------------------

    $keywords = [
        "urgent",
        "verify your account",
        "click here",
        "reset password",
        "bank alert",
        "update account",
        "confirm identity",
        "limited time",
        "account suspended",
        "immediately",
        "unusual activity",
        "security alert"
    ];

    $foundKeywords = [];

    foreach ($keywords as $keyword) {

        if (stripos($emailText, $keyword) !== false) {
            $foundKeywords[] = $keyword;
        }
    }

    if (!empty($foundKeywords)) {

        $score += min(count($foundKeywords) * 10, 30);

        $reasons[] =
            "Suspicious phrases detected: " .
            implode(", ", $foundKeywords);
    }


    // --------------------------------------
    // 2. Credential theft detection
    // --------------------------------------

    $credentialPatterns = [
        "enter your password",
        "share your password",
        "confirm your password",
        "provide your otp",
        "share your otp",
        "enter your otp",
        "credit card number",
        "bank account details",
        "account credentials",
        "login credentials"
    ];

    $credentialFound = [];

    foreach ($credentialPatterns as $pattern) {

        if (stripos($emailText, $pattern) !== false) {
            $credentialFound[] = $pattern;
        }
    }

    if (!empty($credentialFound)) {

        $score += 25;

        $reasons[] =
            "Possible credential theft request detected: " .
            implode(", ", $credentialFound);
    }


    // --------------------------------------
    // 3. Urgency and threatening language
    // --------------------------------------

    $urgencyPatterns = [
        "account will be blocked",
        "account will be suspended",
        "within 24 hours",
        "act now",
        "immediate action required",
        "final warning",
        "your account is locked",
        "failure to respond"
    ];

    $urgencyFound = [];

    foreach ($urgencyPatterns as $pattern) {

        if (stripos($emailText, $pattern) !== false) {
            $urgencyFound[] = $pattern;
        }
    }

    if (!empty($urgencyFound)) {

        $score += 20;

        $reasons[] =
            "Urgency or threatening language detected: " .
            implode(", ", $urgencyFound);
    }


    // --------------------------------------
    // 4. Suspicious links
    // --------------------------------------

    preg_match_all(
        '~https?://[^\s<>"\']+~i',
        $emailText,
        $matches
    );

    $links = array_unique($matches[0]);

    if (!empty($links)) {

        $score += 10;

        $reasons[] =
            "Email contains " . count($links) .
            " clickable link(s). Links require inspection.";

        foreach ($links as $link) {

            $link = rtrim($link, ".,;!?) ]");

            $host = strtolower(
                parse_url($link, PHP_URL_HOST) ?? ""
            );

            if ($host === "") {
                continue;
            }

            // Check suspicious TLDs
            $tld = strtolower(pathinfo($host, PATHINFO_EXTENSION));

            $suspiciousTlds = [
                "xyz", "top", "click", "work",
                "live", "zip", "mov"
            ];

            if (in_array($tld, $suspiciousTlds, true)) {

                $score += 15;

                $reasons[] =
                    "Link uses a potentially risky domain extension: ." . $tld;
            }

            // Check IP address links
            if (filter_var($host, FILTER_VALIDATE_IP)) {

                $score += 25;

                $reasons[] =
                    "Link uses an IP address instead of a domain name.";
            }

            // Check Punycode
            if (strpos($host, "xn--") !== false) {

                $score += 20;

                $reasons[] =
                    "Link contains a Punycode domain.";
            }

            // Check brand impersonation in link domains
            foreach ($brands as $brand => $officialDomains) {

                if (
                    strpos($host, $brand) !== false &&
                    !isOfficialBrandDomain($host, $officialDomains)
                ) {

                    $score += 20;

                    $reasons[] =
                        "Possible " . ucfirst($brand) .
                        " brand impersonation in link domain: " . $host;
                }
            }
        }
    }


    // --------------------------------------
    // 5. Sender spoofing and brand detection
    // --------------------------------------

    if (
        preg_match(
            '/^From:\s*(.+)$/im',
            $emailText,
            $fromMatch
        )
    ) {

        $fromLine = trim($fromMatch[1]);

        if (
            preg_match(
                '/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/',
                $fromLine,
                $emailMatch
            )
        ) {

            $senderEmail = strtolower($emailMatch[0]);

            $senderDomain = substr(
                strrchr($senderEmail, "@"),
                1
            );

            $senderName = strtolower(
                str_replace($senderEmail, "", $fromLine)
            );

            // Check whether display name claims a known brand
            foreach ($brands as $brand => $officialDomains) {

                if (strpos($senderName, $brand) !== false) {

                    if (
                        !isOfficialBrandDomain(
                            $senderDomain,
                            $officialDomains
                        )
                    ) {

                        $score += 30;

                        $reasons[] =
                            "Possible sender spoofing: display name mentions " .
                            ucfirst($brand) .
                            " but sender domain is " . $senderDomain;
                    }
                }

                // Check for a brand name in a non-official sender domain
                if (
                    strpos($senderDomain, $brand) !== false &&
                    !isOfficialBrandDomain(
                        $senderDomain,
                        $officialDomains
                    )
                ) {

                    $score += 20;

                    $reasons[] =
                        "Sender domain may imitate " .
                        ucfirst($brand) . ": " . $senderDomain;
                }
            }

        } else {

            $reasons[] =
                "From header found, but sender email address could not be extracted.";
        }

    } else {

        $reasons[] =
            "No From header provided. Sender authenticity could not be checked.";
    }


    // --------------------------------------
    // 6. Excessive exclamation marks
    // --------------------------------------

    if (substr_count($emailText, "!") >= 3) {

        $score += 10;

        $reasons[] =
            "Excessive use of exclamation marks.";
    }


    // --------------------------------------
    // 7. Very short message
    // --------------------------------------

    if (strlen(trim($emailText)) < 50) {

        $score += 5;

        $reasons[] =
            "Very short message. Insufficient content for reliable analysis.";
    }


    // --------------------------------------
    // 8. Final risk score
    // --------------------------------------

    $score = min($score, 100);

    if ($score <= 20) {

        $level = "LOW";

    } elseif ($score <= 50) {

        $level = "MEDIUM";

    } else {

        $level = "HIGH";
    }


    if (empty($reasons)) {

        $reasons[] =
            "No major phishing indicators detected by the current rules.";
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

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $emailText = trim($_POST['email_text'] ?? '');

    if ($emailText === "") {

        $dbError = "Please paste email content before analysis.";

    } else {

        $analysis = analyzeEmail($emailText);

        $riskScore = $analysis['score'];
        $riskLevel = $analysis['level'];
        $reasons = $analysis['reasons'];


        // Store results in existing database table
        $stmt = $conn->prepare(
            "INSERT INTO email_scans
            (email_text, risk_score, risk_level)
            VALUES (?, ?, ?)"
        );

        if ($stmt) {

            $stmt->bind_param(
                "sis",
                $emailText,
                $riskScore,
                $riskLevel
            );

            if (!$stmt->execute()) {

                $dbError = "Analysis completed, but database storage failed.";

                error_log("PhishGuard email scan database error: " . $stmt->error);
            }

            $stmt->close();

        } else {

            $dbError = "Could not prepare database statement.";

            error_log("PhishGuard email scan prepare error: " . $conn->error);
        }
    }
}

?>


<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PhishGuard - Email Phishing Detector</title>

    <link rel="stylesheet" href="style.css?v=16">

    <style>

        .email-result {
            margin-top: 25px;
            padding: 20px;
            border-radius: 12px;
            background: #f4f7fb;
        }

        .email-score {
            font-size: 32px;
            font-weight: bold;
            margin: 12px 0;
        }

        .email-low {
            color: #16834b;
        }

        .email-medium {
            color: #b8860b;
        }

        .email-high {
            color: #d93025;
        }

        .email-findings {
            padding-left: 20px;
            line-height: 1.8;
        }

        .email-error {
            margin-top: 15px;
            color: #d93025;
        }

        .email-note {
            margin-top: 15px;
            font-size: 13px;
            color: #555;
        }

    </style>

</head>


<body>

<div class="login-box">

    <h2>Email Phishing Detector</h2>

    <p>
        Analyze email content to identify suspicious phrases,
        sender spoofing, credential theft and potentially harmful links.
    </p>


    <form method="POST">

        <label for="email_text">
            Paste Email Content
        </label>

        <textarea
            id="email_text"
            name="email_text"
            placeholder="Paste complete email content here. Include the From header if available."
            required
            style="
                width:100%;
                height:180px;
                padding:15px;
                border-radius:10px;
                margin-bottom:15px;
                box-sizing:border-box;
            "
        ><?php echo htmlspecialchars($emailText); ?></textarea>


        <button type="submit">
            Analyze Email
        </button>

    </form>


    <?php if ($dbError !== ""): ?>

        <div class="email-error">
            <?php echo htmlspecialchars($dbError); ?>
        </div>

    <?php endif; ?>


    <?php if ($_SERVER["REQUEST_METHOD"] === "POST" && $emailText !== ""): ?>

        <hr>

        <div class="email-result">

            <h3>PhishGuard Analysis Result</h3>

            <p>
                <strong>Risk Score:</strong>
            </p>

            <div class="email-score email-<?php echo strtolower(htmlspecialchars($riskLevel)); ?>">
                <?php echo (int)$riskScore; ?>/100
            </div>


            <p>
                <strong>Risk Level:</strong>

                <?php echo htmlspecialchars($riskLevel); ?>
            </p>


            <h4>Detected Indicators</h4>

            <ul class="email-findings">

                <?php foreach ($reasons as $reason): ?>

                    <li>
                        <?php echo htmlspecialchars($reason); ?>
                    </li>

                <?php endforeach; ?>

            </ul>


            <p>
                <strong>Recommendation:</strong>

                <?php if ($riskLevel === "HIGH"): ?>

                    Do not click suspicious links or provide passwords,
                    OTPs or financial information. Verify the sender
                    through an independent trusted channel.

                <?php elseif ($riskLevel === "MEDIUM"): ?>

                    Review the sender address and all links carefully
                    before taking any action.

                <?php else: ?>

                    No major indicators were detected by the current
                    rules. This does not guarantee that the email is safe.

                <?php endif; ?>

            </p>


            <p class="email-note">
                This analysis uses predefined rules and heuristic scoring.
                It does not guarantee that an email is genuine or malicious.
            </p>

        </div>

    <?php endif; ?>


    <br>

    <a href="awareness.php">
        Back to Awareness Dashboard
    </a>

</div>

</body>

</html>
