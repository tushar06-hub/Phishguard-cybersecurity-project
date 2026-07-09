<?php
session_start();
if(!isset($_SESSION['otp_attempts']))
{
    $_SESSION['otp_attempts'] = 0;
}
if(!isset($_SESSION['otp']))
{
    header("Location: login.php");
    exit();
}

$message="";

if($_SERVER["REQUEST_METHOD"]=="POST")
{
    $userOtp=$_POST['otp'];

    if($userOtp == $_SESSION['otp'])
{
    $_SESSION['otp_attempts'] = 0;

    header("Location: awareness.php");
    exit();
}
else
{
    $_SESSION['otp_attempts']++;

    if($_SESSION['otp_attempts'] >= 3)
    {
        session_destroy();

die('

<!DOCTYPE html>

<html>

<head>

<title>Access Denied</title>

<link rel="stylesheet" href="style.css">

</head>

<body>

<div class="login-box">

<h2 style="color:red;">
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

    $remaining =
    3 - $_SESSION['otp_attempts'];

    $message =
    'Invalid OTP. Attempts Remaining: '
    .$remaining;
}
}
?>

<!DOCTYPE html>

<html>
<head>
<title>OTP Verification</title>
<link rel="stylesheet" href="style.css">
</head>

<body>

<div class="login-box">

<h2>OTP Verification</h2>

<p>
Demo OTP:
<b><?php echo $_SESSION['otp']; ?></b>
</p>

<p style="color:red;">
<?php echo $message; ?>
</p>

<form method="POST">

<input
type="text"
name="otp"
placeholder="Enter OTP"
required>

<button type="submit">
Verify OTP
</button>

</form>

</div>

</body>
</html>
