<?php
$br = (php_sapi_name() == "cli")? "":"<br>";

if(!extension_loaded('smtpmail')) {
	dl('smtpmail.' . PHP_SHLIB_SUFFIX);
}
$module = 'smtpmail';
if (extension_loaded($module)) {
	$str = "Module $module is compiled into PHP";
} else {
	$str = "Module $module is not compiled into PHP";
}
echo "$str\n";
?>
