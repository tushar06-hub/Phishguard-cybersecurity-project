
<?php

require_once "otp_config.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: otp_login.php");
    exit();
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

if ($email === '' || $password === '') {
    die("Email and password are required.");
}

// Verify user against existing database
$stmt = $conn->prepare(
    "SELECT id, name, email, password_hash
     FROM users
     WHERE email = ?
     LIMIT 1"
);

$stmt->bind_param("s", $email);
$stmt->execute();

$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

if (!$user || !password_verify($password, $user['password_hash'])) {
    die("Invalid email or password.");
}

// Generate OTP
$otp = (string) random_int(100000, 999999);
$otpHash = password_hash($otp, PASSWORD_DEFAULT);
$expiry = date("Y-m-d H:i:s", time() + 300);

// Invalidate previous pending OTPs for this user
$stmt = $conn->prepare(
    "UPDATE otp_requests
     SET verified_at = NOW()
     WHERE user_id = ? AND verified_at IS NULL"
);

$stmt->bind_param("i", $user['id']);
$stmt->execute();
$stmt->close();

// Save new OTP hash
$stmt = $conn->prepare(
    "INSERT INTO otp_requests
     (user_id, otp_hash, expires_at)
     VALUES (?, ?, ?)"
);

$stmt->bind_param(
    "iss",
    $user['id'],
    $otpHash,
    $expiry
);

if (!$stmt->execute()) {
    die("Could not create OTP.");
}

$otpId = $conn->insert_id;
$stmt->close();

// Send email
$mail = new PHPMailer(true);

try {

    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->SMTPAuth = true;
    $mail->Username = SMTP_USERNAME;
    $mail->Password = SMTP_PASSWORD;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = 587;

    $mail->setFrom(SMTP_USERNAME, 'PhishGuard Security');
    $mail->addAddress($user['email'], $user['name']);

    $mail->isHTML(true);
    $mail->Subject = 'Your PhishGuard Verification OTP';

    $mail->Body = "
        <h2>PhishGuard Verification</h2>
        <p>Hello " . htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8') . ",</p>
        <p>Your verification OTP is:</p>
        <h1 style='letter-spacing:5px;'>$otp</h1>
        <p>This OTP expires in 5 minutes.</p>
        <p>Do not share this code with anyone.</p>
    ";

    $mail->AltBody = "Your PhishGuard OTP is $otp. It expires in 5 minutes.";

    $mail->send();

    // Keep only the pending authentication details in the session
    $_SESSION['pending_user_id'] = $user['id'];
    $_SESSION['pending_otp_id'] = $otpId;

    header("Location: otp_verify.php");
    exit();

} catch (Exception $e) {

    // Invalidate the OTP if delivery failed
    $stmt = $conn->prepare(
        "UPDATE otp_requests SET verified_at = NOW() WHERE id = ?"
    );

    $stmt->bind_param("i", $otpId);
    $stmt->execute();
    $stmt->close();

    die("OTP email could not be sent. Check your SMTP configuration.");
}

?>
