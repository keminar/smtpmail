--TEST--
Check for smtpmail ssl connect
--SKIPIF--
<?php if (!extension_loaded("smtpmail") || !extension_loaded("openssl")) print "skip"; ?>
--FILE--
<?php
$smtpmail = new SmtpMail("smtp.gmail.com", 465);
var_dump($smtpmail);
?>
--EXPECT--
object(SmtpMail)#1 (1) {
  ["hostname"]=>
  string(14) "smtp.gmail.com:465"
}
