<?php
// Good: User input sanitized with mysqli_real_escape_string
$user_id = $_GET['id'];
$escaped_id = mysqli_real_escape_string($connection, $user_id);
$query = "SELECT * FROM users WHERE id = '$escaped_id'";
$result = mysqli_query($connection, $query);
?>

