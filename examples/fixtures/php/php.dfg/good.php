<?php
$a = 1;
$b = $a;
echo $b;
function callee() {}
function caller() { callee(); }
