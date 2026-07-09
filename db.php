<?php

$host="localhost";
$user="tushar";
$password="tushar@2006";
$dbname="phishguard";

$conn = new mysqli(
$host,
$user,
$password,
$dbname
);

if($conn->connect_error)
{
die("Connection Failed");
}

?>
