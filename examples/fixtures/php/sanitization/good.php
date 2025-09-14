<?php
$name = $_GET['name'];
$name = sanitize($name);
echo $name;
