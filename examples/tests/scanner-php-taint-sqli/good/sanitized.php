<?php
// GOOD: User input sanitized before use in SQL.
$id = $_GET['id'] ?? '';
$id = mysqli_real_escape_string($conn, $id);
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
mysqli_query($conn, $query);
