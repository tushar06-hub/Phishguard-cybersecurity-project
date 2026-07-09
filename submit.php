<?php

session_start();

include("db.php");

$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';

$stmt = $conn->prepare(
"SELECT id,name,email,password_hash
 FROM users
 WHERE email=?"
);

$stmt->bind_param("s",$email);

$stmt->execute();

$result = $stmt->get_result();

if($result->num_rows == 1)
{
    $user = $result->fetch_assoc();

    if(password_verify(
        $password,
        $user['password_hash']
    ))
    {
        $otp = rand(100000,999999);

        $_SESSION['otp'] = $otp;
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['name'] = $user['name'];

        header("Location: otp.php");
        exit();
    }
    else
    {
        die("Invalid Password");
    }
}
else
{
    die("User Not Found");
}

?>
