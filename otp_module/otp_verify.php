
<?php

require_once "otp_config.php";

if (
    !isset($_SESSION['pending_user_id']) ||
    !isset($_SESSION['pending_otp_id'])
) {
    header("Location: otp_login.php");
    exit();
}

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $enteredOtp = trim($_POST['otp'] ?? '');

    if (!preg_match('/^[0-9]{6}$/', $enteredOtp)) {

        $message = "Enter a valid six-digit OTP.";

    } else {

        $userId = (int) $_SESSION['pending_user_id'];
        $otpId = (int) $_SESSION['pending_otp_id'];

        $stmt = $conn->prepare(
            "SELECT otp_hash, expires_at, attempts
             FROM otp_requests
             WHERE id = ? AND user_id = ?
             AND verified_at IS NULL
             LIMIT 1"
        );

        $stmt->bind_param("ii", $otpId, $userId);
        $stmt->execute();

        $result = $stmt->get_result();
        $otpRecord = $result->fetch_assoc();
        $stmt->close();

        if (!$otpRecord) {

            $message = "OTP is invalid or already used.";

        } elseif (strtotime($otpRecord['expires_at']) < time()) {

            $stmt = $conn->prepare(
                "UPDATE otp_requests
                 SET verified_at = NOW()
                 WHERE id = ?"
            );

            $stmt->bind_param("i", $otpId);
            $stmt->execute();
            $stmt->close();

            $message = "OTP expired. Please login again.";

            unset(
                $_SESSION['pending_user_id'],
                $_SESSION['pending_otp_id']
            );

        } elseif ((int)$otpRecord['attempts'] >= 3) {

            $message = "Maximum attempts reached. Login again.";

            $stmt = $conn->prepare(
                "UPDATE otp_requests
                 SET verified_at = NOW()
                 WHERE id = ?"
            );

            $stmt->bind_param("i", $otpId);
            $stmt->execute();
            $stmt->close();

            unset(
                $_SESSION['pending_user_id'],
                $_SESSION['pending_otp_id']
            );

        } else {

            // Count this attempt
            $stmt = $conn->prepare(
                "UPDATE otp_requests
                 SET attempts = attempts + 1
                 WHERE id = ?"
            );

            $stmt->bind_param("i", $otpId);
            $stmt->execute();
            $stmt->close();

            if (password_verify($enteredOtp, $otpRecord['otp_hash'])) {

                // Mark OTP as used
                $stmt = $conn->prepare(
                    "UPDATE otp_requests
                     SET verified_at = NOW()
                     WHERE id = ? AND verified_at IS NULL"
                );

                $stmt->bind_param("i", $otpId);
                $stmt->execute();

                $success = $stmt->affected_rows === 1;
                $stmt->close();

                if ($success) {

                    session_regenerate_id(true);

                    $_SESSION['user_id'] = $userId;
                    $_SESSION['authenticated'] = true;

                    unset(
                        $_SESSION['pending_user_id'],
                        $_SESSION['pending_otp_id']
                    );

                    header("Location: otp_success.php");
                    exit();

                } else {
                    $message = "OTP is invalid or already used.";
                }

            } else {

                $remaining = 2 - (int)$otpRecord['attempts'];

                if ($remaining <= 0) {

                    $stmt = $conn->prepare(
                        "UPDATE otp_requests
                         SET verified_at = NOW()
                         WHERE id = ?"
                    );

                    $stmt->bind_param("i", $otpId);
                    $stmt->execute();
                    $stmt->close();

                    unset(
                        $_SESSION['pending_user_id'],
                        $_SESSION['pending_otp_id']
                    );

                    $message = "Maximum attempts reached. Login again.";

                } else {

                    $message = "Incorrect OTP. Attempts remaining: " . $remaining;
                }
            }
        }
    }
}


// Get the actual remaining OTP expiry time from database
$remainingSeconds = 0;

if (
    isset($_SESSION['pending_user_id']) &&
    isset($_SESSION['pending_otp_id'])
) {

    $userId = (int) $_SESSION['pending_user_id'];
    $otpId = (int) $_SESSION['pending_otp_id'];

    $stmt = $conn->prepare(
        "SELECT expires_at
         FROM otp_requests
         WHERE id = ? AND user_id = ?
         AND verified_at IS NULL
         LIMIT 1"
    );

    $stmt->bind_param("ii", $otpId, $userId);
    $stmt->execute();

    $result = $stmt->get_result();
    $expiryRecord = $result->fetch_assoc();
    $stmt->close();

    if ($expiryRecord) {
        $remainingSeconds = max(
            0,
            strtotime($expiryRecord['expires_at']) - time()
        );
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>PhishGuard - OTP Verification</title>

    <link rel="stylesheet" href="../style.css?v=15">

    <style>
        .otp-timer {
            margin: 18px 0;
            padding: 12px;
            border-radius: 8px;
            background: #eef4fa;
            text-align: center;
        }

        .otp-timer p {
            margin: 0 0 5px;
            font-size: 14px;
            color: #555;
        }

        #countdown {
            font-size: 25px;
            font-weight: bold;
            color: #174f80;
            letter-spacing: 2px;
        }

        #timer-status {
            margin-top: 5px;
            font-size: 13px;
            color: #555;
        }

        .otp-expired {
            color: #d93025 !important;
        }

        .otp-disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>

</head>

<body class="otp-page">

    <div class="otp-container">

        <div class="otp-icon">
            <span>✉</span>
        </div>

        <h2>Email Verification</h2>

        <p class="otp-subtitle">
            We've sent a six-digit verification code to your registered email address.
        </p>

        <div class="otp-info">
            <span>🔒</span>
            Your account is protected by an additional security layer.
        </div>

        <!-- OTP Countdown Timer -->
        <div class="otp-timer">

            <p>OTP expires in</p>

            <div id="countdown">05:00</div>

            <div id="timer-status">
                Please verify before the timer expires.
            </div>

        </div>

        <?php if ($message !== ""): ?>
            <div class="otp-message">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" autocomplete="off" id="otpForm">

            <label for="otp">Enter Verification Code</label>

            <input
                type="text"
                id="otp"
                name="otp"
                placeholder="000000"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                autocomplete="one-time-code"
                required
            >

            <button type="submit" id="verifyButton">
                Verify OTP
            </button>

        </form>

        <p class="otp-footer">
            Didn't receive the code? Check your spam folder.
        </p>

        <a href="otp_login.php" class="otp-back">
            Back to Login
        </a>

    </div>


    <script>

        // Actual remaining time supplied by PHP from the database
        let timeLeft = <?php echo (int)$remainingSeconds; ?>;

        const countdown = document.getElementById("countdown");
        const timerStatus = document.getElementById("timer-status");
        const otpInput = document.getElementById("otp");
        const verifyButton = document.getElementById("verifyButton");
        const otpForm = document.getElementById("otpForm");

        function updateTimer() {

            let minutes = Math.floor(timeLeft / 60);
            let seconds = timeLeft % 60;

            countdown.textContent =
                String(minutes).padStart(2, '0') + ":" +
                String(seconds).padStart(2, '0');

            if (timeLeft <= 0) {

                countdown.textContent = "00:00";

                countdown.classList.add("otp-expired");

                timerStatus.textContent =
                    "OTP Expired! Please login again.";

                timerStatus.classList.add("otp-expired");

                otpInput.disabled = true;
                verifyButton.disabled = true;

                otpInput.classList.add("otp-disabled");
                verifyButton.classList.add("otp-disabled");

                return;
            }

            timeLeft--;
        }

        // Display immediately
        updateTimer();

        // Update every second
        const timerInterval = setInterval(function () {

            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                updateTimer();
                return;
            }

            updateTimer();

        }, 1000);

        // Prevent submission after the countdown expires
        otpForm.addEventListener("submit", function(event) {

            if (timeLeft <= 0) {
                event.preventDefault();
                alert("OTP has expired. Please login again.");
            }

        });

    </script>

</body>
</html>
