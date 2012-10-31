--TEST--
Check for smtpmail empty user login 
--SKIPIF--
<?php 
require "config.inc";
if (!extension_loaded("smtpmail")) print "skip"; 
if ($smtp_from == "" || $smtp_to == "") print "skip";
?>
--FILE--
<?php
error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);
include "config.inc";
$smtpmail = new SmtpMail($smtp_host, $smtp_port, $smtp_timeout, $smtp_charset, $smtp_delimiter, 0);
$smtpmail->login("", "");
echo (int)$smtpmail->from($smtp_from, $smtp_from_name);
?>
--EXPECT--
0
