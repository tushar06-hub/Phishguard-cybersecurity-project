<?php

include("db.php");

$users =
$conn->query(
"SELECT COUNT(*) AS total
FROM users"
)->fetch_assoc()['total'];

$credentials =
$conn->query(
"SELECT COUNT(*) AS total
FROM credentials"
)->fetch_assoc()['total'];

$urlScans =
$conn->query(
"SELECT COUNT(*) AS total
FROM url_scans"
)->fetch_assoc()['total'];

$emailScans =
$conn->query(
"SELECT COUNT(*) AS total
FROM email_scans"
)->fetch_assoc()['total'];

$highUrls =
$conn->query(
"SELECT COUNT(*) AS total
FROM url_scans
WHERE risk_level='HIGH'"
)->fetch_assoc()['total'];

$highEmails =
$conn->query(
"SELECT COUNT(*) AS total
FROM email_scans
WHERE risk_level='HIGH'"
)->fetch_assoc()['total'];

?>

<!DOCTYPE html>

<html>

<head>

<title>PhishGuard Dashboard</title>

<link rel="stylesheet" href="style.css">

</head>

<body>

<div class="dashboard">

<h1>PhishGuard Security Dashboard</h1>

<div class="dashboard-grid">

<div class="card">
<h3>Registered Users</h3>
<p><?php echo $users; ?></p>
</div>

<div class="card">
<h3>Login Attempts</h3>
<p><?php echo $credentials; ?></p>
</div>

<div class="card">
<h3>URL Scans</h3>
<p><?php echo $urlScans; ?></p>
</div>

<div class="card">
<h3>Email Scans</h3>
<p><?php echo $emailScans; ?></p>
</div>

<div class="card">
<h3>High Risk URLs</h3>
<p><?php echo $highUrls; ?></p>
</div>

<div class="card">
<h3>High Risk Emails</h3>
<p><?php echo $highEmails; ?></p>
</div>

</div>

<br>

<a href="awareness.php" class="btn">
Back To Security Center
</a>

</div>

</body>

</html>

