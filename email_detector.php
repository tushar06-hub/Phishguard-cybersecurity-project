<?php

include("db.php");

$riskScore = 0;
$riskLevel = "";
$reasons = [];

if($_SERVER["REQUEST_METHOD"]=="POST")
{
    $emailText = trim($_POST['email_text']);

    $keywords = [
        "urgent",
        "verify your account",
        "click here",
        "reset password",
        "bank alert",
        "update account",
        "confirm identity",
        "limited time",
        "otp",
        "password"
    ];

    foreach($keywords as $keyword)
    {
        if(stripos($emailText,$keyword)!==false)
        {
            $riskScore += 15;
            $reasons[] =
            "Suspicious phrase detected: ".$keyword;
        }
    }

    if(preg_match('/https?:\/\//i',$emailText))
    {
        $riskScore += 20;

        $reasons[] =
        "Contains clickable link";
    }

    if(substr_count($emailText,'!') >= 3)
    {
        $riskScore += 10;

        $reasons[] =
        "Excessive use of exclamation marks";
    }

    if(strlen($emailText) < 50)
    {
        $riskScore += 5;

        $reasons[] =
        "Very short message";
    }

    if($riskScore <= 20)
    {
        $riskLevel = "LOW";
    }
    elseif($riskScore <= 50)
    {
        $riskLevel = "MEDIUM";
    }
    else
    {
        $riskLevel = "HIGH";
    }

    $stmt = $conn->prepare(
    "INSERT INTO email_scans
    (email_text,risk_score,risk_level)
    VALUES
    (?,?,?)"
    );

    $stmt->bind_param(
    "sis",
    $emailText,
    $riskScore,
    $riskLevel
    );

    $stmt->execute();
}

?>

<!DOCTYPE html>

<html>

<head>

<title>Email Phishing Detector</title>

<link rel="stylesheet" href="style.css">

</head>

<body>

<div class="login-box">

<h2>Email Phishing Detector</h2>

<form method="POST">

<textarea
name="email_text"
placeholder="Paste Email Content Here"
required
style="
width:100%;
height:180px;
padding:15px;
border-radius:10px;
margin-bottom:15px;
"></textarea>

<button type="submit">
Analyze Email
</button>

</form>

<?php if(isset($emailText)) { ?>

<hr>

<h3>Analysis Result</h3>

<p>

<b>Risk Score:</b>

<?php echo $riskScore; ?>

</p>

<p>

<b>Risk Level:</b>

<?php echo $riskLevel; ?>

</p>

<h4>Detected Indicators</h4>

<ul>

<?php

if(count($reasons)==0)
{
    echo "<li>No major phishing indicators detected.</li>";
}
else
{
    foreach($reasons as $reason)
    {
        echo "<li>".$reason."</li>";
    }
}

?>

</ul>

<?php } ?>

</div>

</body>

</html>
