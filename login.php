
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>SecureTrust Bank - Login</title>

    <link rel="stylesheet" href="style.css?v=10">
</head>

<body class="login-page">

    <div class="login-box">

        <h2>Welcome Back</h2>

        <p class="login-subtitle">
            Login to your SecureTrust account
        </p>

        <form action="otp_module/otp_send.php"
              method="POST"
              autocomplete="off">

            <img
                src="https://cdn-icons-png.flaticon.com/512/295/295128.png"
                class="form-image"
                alt="Login icon"
            >

            <label for="email">Email Address</label>

            <input
                type="email"
                id="email"
                name="email"
                placeholder="Enter your email"
                autocomplete="off"
                required
            >

            <label for="password">Password</label>

            <input
                type="password"
                id="password"
                name="password"
                placeholder="Enter your password"
                autocomplete="new-password"
                required
            >

            <button type="submit">
                Login Securely
            </button>

        </form>

        <p class="register-link">
            New User?
            <a href="register.php">Register Here</a>
        </p>

        <p class="security-note">
            Your account is protected with email OTP verification.
        </p>

    </div>

</body>
</html>
