<!DOCTYPE html>
<html>
<head>
<title>Login</title>
<link rel="stylesheet" href="style.css">
</head>

<body class="login-page">

<div class="login-box">

<h2>Internet Banking Login</h2>

<form action="submit.php" method="POST" autocomplete="off">
<img
src="https://cdn-icons-png.flaticon.com/512/295/295128.png"
class="form-image">
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
Login
</button>

</form>
<br>

<p style="text-align:center;">

New User?

<a href="register.php">
Register Here
</a>

</p>
</div>

</body>
</html>
