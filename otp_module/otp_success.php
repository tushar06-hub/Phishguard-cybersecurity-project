
<?php

require_once "otp_config.php";

if (
    empty($_SESSION['authenticated']) ||
    empty($_SESSION['user_id'])
) {
    header("Location: otp_login.php");
    exit();
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PhishGuard - Authentication Successful</title>

    <link rel="stylesheet" href="../style.css?v=15">

</head>

<body class="mfa-success-page">

    <div class="mfa-success-card">

        <div class="success-icon">
            &#10003;
        </div>

        <span class="success-label">
            AUTHENTICATION VERIFIED
        </span>

        <h1>You're Successfully Verified!</h1>

        <p class="success-description">
            Your identity has been successfully verified
            through Multi-Factor Authentication.
        </p>

        <div class="verification-details">

            <div class="verification-item">
                <span class="verification-check">&#10003;</span>

                <div>
                    <strong>Password Verification</strong>
                    <p>Your password was verified successfully.</p>
                </div>
            </div>

            <div class="verification-item">
                <span class="verification-check">&#10003;</span>

                <div>
                    <strong>Email OTP Verification</strong>
                    <p>Your email verification code was accepted.</p>
                </div>
            </div>

        </div>

        <div class="secure-message">
            <span>🔐</span>
            Your authentication session is now active.
        </div>

        <a href="../awareness.php" class="mfa-button">
            Continue to PhishGuard
            <span>&rarr;</span>
        </a>

        <p class="mfa-footer">
            PhishGuard Security System
        </p>

    </div>

</body>
</html>
