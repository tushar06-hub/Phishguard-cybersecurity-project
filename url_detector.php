<?php

include("db.php");

$riskScore = 0;
$riskLevel = "";
$reasons = [];

if($_SERVER["REQUEST_METHOD"]=="POST")
{
    $url = trim($_POST['url']);

    $keywords = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "signin",
        "banking"
    ];

    foreach($keywords as $keyword)
    {
        if(stripos($url,$keyword)!==false)
        {
            $riskScore += 20;
            $reasons[] = "Contains suspicious keyword: ".$keyword;
        }
    }

    $hyphenCount = substr_count($url,"-");

    if($hyphenCount >= 2)
    {
        $riskScore += 15;
        $reasons[] = "Too many hyphens";
    }

    if(preg_match('/https?:\/\/(\d{1,3}\.){3}\d{1,3}/',$url))
    {
        $riskScore += 40;
        $reasons[] = "Uses IP address instead of domain";
    }

    if(strlen($url) > 50)
    {
        $riskScore += 15;
        $reasons[] = "Unusually long URL";
    }

    $suspiciousTlds = [
        ".xyz",
        ".top",
        ".click",
        ".work",
        ".live"
    ];

    foreach($suspiciousTlds as $tld)
    {
        if(stripos($url,$tld)!==false)
        {
            $riskScore += 20;
            $reasons[] = "Suspicious TLD: ".$tld;
        }
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
    "INSERT INTO url_scans
    (url,risk_score,risk_level)
    VALUES
    (?,?,?)"
    );

    $stmt->bind_param(
    "sis",
    $url,
    $riskScore,
    $riskLevel
    );

    $stmt->execute();
}
?>

<!DOCTYPE html>

<html>
<head>
<title>Phishing URL Detector</title>
<link rel="stylesheet" href="style.css">
</head>

<body>

<div class="login-box">

<h2>Phishing URL Detector</h2>

<form method="POST">

<input
type="text"
name="url"
placeholder="Paste URL Here"
required>

<button type="submit">
Scan URL
</button>

</form>

<?php if(isset($url)) { ?>

<hr>

<h3>Scan Result</h3>

<p>
<b>URL:</b>
<?php echo htmlspecialchars($url); ?>
</p>

<p>
<b>Risk Score:</b>
<?php echo $riskScore; ?>
</p>

<p>
<b>Risk Level:</b>
<?php echo $riskLevel; ?>
</p>

<h4>Detected Issues</h4>

<ul>

<?php

if(count($reasons)==0)
{
    echo "<li>No major phishing indicators found.</li>";
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
