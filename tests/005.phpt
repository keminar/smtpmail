--TEST--
Check for smtpmail empty from
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
$smtpmail->login($smtp_user, $smtp_pass);
$smtpmail->from("", "");
$smtpmail->to($smtp_to, $smtp_to_name);
echo (int)$smtpmail->send($smtp_subject, $smtp_body);
$smtpmail->close();
?>
--EXPECT--
0
