<?php
// Safe usage: no dynamic command execution
$name = $_GET['name'] ?? '';
$clean = strip_tags($name);
echo $clean;

