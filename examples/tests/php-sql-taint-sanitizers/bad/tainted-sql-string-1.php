<?php
// Bad: User input flows directly into SQL string without sanitization
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $user_id";
$result = mysqli_query($connection, $query);
?>

