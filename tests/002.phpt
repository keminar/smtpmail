--TEST--
Check for smtpmail connect
--SKIPIF--
<?php if (!extension_loaded("smtpmail")) print "skip"; ?>
--FILE--
<?php
$smtpmail = new SmtpMail("smtp.qq.com", 25);
var_dump($smtpmail);
?>
--EXPECT--
object(SmtpMail)#1 (1) {
  ["hostname"]=>
  string(14) "smtp.qq.com:25"
}
