
<?php

include("db.php");

$message = "";
$messageType = "";

// Keep the log in the main PhishGuard directory.
$logFile = __DIR__ . "/register_log.txt";

function writeDemoLog($event, $name, $email, $status, $reason = "")
{
    global $logFile;

    $time = date("Y-m-d H:i:s");
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';

    // Prevent newlines in user input from creating fake log entries.
    $name = str_replace(["\r", "\n"], " ", $name);
    $email = str_replace(["\r", "\n"], " ", $email);
    $reason = str_replace(["\r", "\n"], " ", $reason);

    $log =
        "====================================\n" .
        "Time: $time\n" .
        "Event: $event\n" .
        "Name: $name\n" .
        "Email: $email\n" .
        "IP Address: $ip\n" .
        "Status: $status\n" .
        "Details: $reason\n" .
        "Simulation: PhishGuard Awareness Demo\n" .
        "====================================\n\n";

    $saved = file_put_contents(
        $logFile,
        $log,
        FILE_APPEND | LOCK_EX
    );

    if ($saved === false) {
        error_log("PhishGuard: Could not write to register_log.txt");
    }
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $name = trim($_POST['name'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Record registration attempt.
    writeDemoLog(
        "Registration Attempt",
        $name,
        $email,
        "Received"
    );

    if ($name == "" || $email == "" || $password == "") {

        $message = "Please fill in all fields.";
        $messageType = "error";

        writeDemoLog(
            "Registration",
            $name,
            $email,
            "FAILED",
            "Required fields were missing"
        );

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $message = "Invalid email address! Please enter a valid email.";
        $messageType = "error";

        writeDemoLog(
            "Registration",
            $name,
            $email,
            "FAILED",
            "Invalid email format"
        );

    } else {

        $hashedPassword = password_hash(
            $password,
            PASSWORD_DEFAULT
        );

        $stmt = $conn->prepare(
            "INSERT INTO users (name, email, password_hash)
             VALUES (?, ?, ?)"
        );

        if ($stmt) {

            $stmt->bind_param(
                "sss",
                $name,
                $email,
                $hashedPassword
            );

            try {

                if ($stmt->execute()) {

                    $message = "Registration Successful! You can now login.";
                    $messageType = "success";

                    writeDemoLog(
                        "New User Registration",
                        $name,
                        $email,
                        "SUCCESS",
                        "New account created in database"
                    );
                }

            } catch (mysqli_sql_exception $e) {

                if ($e->getCode() == 1062) {

                    $message = "This email is already registered. Please use another email address.";
                    $messageType = "error";

                    writeDemoLog(
                        "New User Registration",
                        $name,
                        $email,
                        "FAILED",
                        "Duplicate email registration attempt"
                    );

                } else {

                    $message = "Registration failed. Please try again.";
                    $messageType = "error";

                    error_log("PhishGuard registration error: " . $e->getMessage());

                    writeDemoLog(
                        "New User Registration",
                        $name,
                        $email,
                        "FAILED",
                        "Database error"
                    );
                }
            }

            $stmt->close();

        } else {

            $message = "Database error. Please try again.";
            $messageType = "error";

            writeDemoLog(
                "New User Registration",
                $name,
                $email,
                "FAILED",
                "Database statement preparation failed"
            );
        }
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>SecureTrust Bank - Register</title>

    <link rel="stylesheet" href="style.css?v=10">

</head>

<body class="register-page">

    <div class="login-box">

        <h2>Create Account</h2>

        <p class="register-subtitle">
            Join SecureTrust Banking
        </p>

        <img
            src="https://cdn-icons-png.flaticon.com/512/3135/3135715.png"
            class="form-image"
            alt="Registration icon"
        >

        <?php if ($message != ""): ?>

            <div class="register-message <?php echo htmlspecialchars($messageType); ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>

        <?php endif; ?>

        <form method="POST" action="register.php" autocomplete="off">

            <label for="name">Full Name</label>

            <input
                type="text"
                id="name"
                name="name"
                placeholder="Enter your full name"
                autocomplete="off"
                required
            >

            <label for="email">Email Address</label>

            <input
                type="text"
                id="email"
                name="email"
                placeholder="Enter your email address"
                autocomplete="off"
                required
            >

            <label for="password">Create Password</label>

            <input
                type="password"
                id="password"
                name="password"
                placeholder="Create a password"
                autocomplete="new-password"
                required
            >

            <button type="submit">
                Create Account
            </button>

        </form>

        <p class="register-link">
            Already have an account?
            <a href="login.php">Login Here</a>
        </p>

        <p class="security-note">
            Your information is protected with password hashing.
        </p>

    </div>

</body>
</html>
