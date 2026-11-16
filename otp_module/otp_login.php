
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard - OTP Login</title>
    <link rel="stylesheet" href="../style.css">
</head>

<body class="login-page">

<div class="login-box">

    <h2>Secure Login with OTP</h2>
    <p class="login-subtitle">Enter your registered credentials</p>

    <form action="otp_send.php" method="POST" autocomplete="off">

        <label>Email Address</label>
        <input type="email" name="email"
               placeholder="Enter your email" required>

        <label>Password</label>
        <input type="password" name="password"
               placeholder="Enter your password"
               autocomplete="new-password" required>

        <button type="submit">Login and Send OTP</button>

    </form>

    <p class="register-link">
        <a href="../login.php">Return to Original Login</a>
    </p>

</div>

</body>
</html>
