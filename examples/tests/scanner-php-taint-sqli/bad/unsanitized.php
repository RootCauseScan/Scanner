<?php
// BAD: User input concatenated into SQL (scanner must detect taint flow).
$id = $_GET['id'] ?? '';
$query = "SELECT * FROM users WHERE id = '" . $id . "'";
mysqli_query($conn, $query);
