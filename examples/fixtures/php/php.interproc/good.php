<?php
function id($p) { return $p; }
$y = sanitize(id($_GET['name']));
echo $y;
