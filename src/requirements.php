<?php
//library requirements
$functions = array('gmp_mul');
foreach ($functions as $function)
{
	if (!function_exists($function))
	{
		die(json_encode(array("code" => 408, "error" => 'Function '.$function.' is unavailable. Please make sure php_gmp extension is available')));
	}
}