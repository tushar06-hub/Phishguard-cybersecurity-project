<?php

session_start();

if (!isset($_SESSION['otp_attempts'])) {
    $_SESSION['otp_attempts'] = 0;
}

if (!isset($_SESSION['otp'])) {
    header("Location: login.php");
    exit();
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $userOtp = trim($_POST['otp'] ?? '');

    if (
        preg_match('/^[0-9]{6}$/', $userOtp) &&
        hash_equals((string)$_SESSION['otp'], $userOtp)
    ) {

        unset($_SESSION['otp']);
        unset($_SESSION['otp_attempts']);

        session_regenerate_id(true);

        header("Location: awareness.php");
        exit();

    } else {

        $_SESSION['otp_attempts']++;

        if ($_SESSION['otp_attempts'] >= 3) {

            session_unset();
            session_destroy();

            die('
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <link rel="stylesheet" href="style.css">
            </head>
            <body class="otp-page">

                <div class="login-box">
                    <h2 style="color:#bd3c3c;">
                        Access Denied
                    </h2>

                    <p>
                        Maximum OTP attempts exceeded.
                    </p>

                    <p>
                        Please login again to continue.
                    </p>

                    <br>

                    <a href="login.php" class="btn">
                        Back To Login
                    </a>
                </div>

            </body>
            </html>
            ');
        }

        $remaining = 3 - $_SESSION['otp_attempts'];

        $message = "Invalid OTP. Attempts remaining: " . $remaining;
    }
}
?>

<!DOCTYPE html>
<html>

<head>
    <title>SecureTrust Bank | OTP Verification</title>

    <link rel="stylesheet" href="style.css?v=3">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body class="otp-page">

    <div class="login-box">

        <div class="form-image">
            <span style="font-size:45px;">🔐</span>
        </div>

        <h2>Verify Your Identity</h2>

        <p class="otp-description">
            Enter the six-digit verification code to continue
            securely to your account.
        </p>

        <!-- Temporary development display -->
        <div class="security-banner">
            Development OTP:
            <strong>
                <?php echo htmlspecialchars((string)$_SESSION['otp']); ?>
            </strong>
        </div>

        <br>

        <?php if (!empty($message)): ?>
            <p style="color:#bd3c3c; margin-bottom:15px;">
                <?php echo htmlspecialchars($message); ?>
            </p>
        <?php endif; ?>

        <form method="POST">

            <input
                type="text"
                name="otp"
                class="otp-input"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                placeholder="000000"
                autocomplete="one-time-code"
                required
            >

            <button type="submit">
                Verify & Continue
            </button>

        </form>

        <p>
            Protected by SecureTrust authentication
        </p>

    </div>

</body>
</html>
