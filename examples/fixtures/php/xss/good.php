<?php
$name = $_GET['name'];
$clean = strip_tags($name);
echo $clean;
