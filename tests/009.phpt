--TEST--
Check for smtpmail empty host 
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
$smtpmail = new SmtpMail("");
$smtpmail->login($smtp_user, $smtp_pass);
$smtpmail->from($smtp_from, $smtp_from_name);
$smtpmail->to($smtp_to, $smtp_to_name);
$smtpmail->cc($smtp_cc, $smtp_cc_name);
$smtpmail->bcc($smtp_bcc, $smtp_bcc_name);
$smtpmail->attachment($smtp_attachment, $smtp_attachment_name);
echo (int)$smtpmail->send($smtp_subject, $smtp_body);
$smtpmail->close();
?>
--EXPECT--
0
