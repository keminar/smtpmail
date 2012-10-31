dnl $Id$
dnl config.m4 for extension smtpmail

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary. This file will not work
dnl without editing.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(smtpmail, for smtpmail support,
dnl Make sure that the comment is aligned:
dnl [  --with-smtpmail             Include smtpmail support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(smtpmail, whether to enable smtpmail support,
dnl Make sure that the comment is aligned:
[  --enable-smtpmail           Enable smtpmail support])

if test "$PHP_SMTPMAIL" != "no"; then
  dnl Write more examples of tests here...

  dnl # --with-smtpmail -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/smtpmail.h"  # you most likely want to change this
  dnl if test -r $PHP_SMTPMAIL/$SEARCH_FOR; then # path given as parameter
  dnl   SMTPMAIL_DIR=$PHP_SMTPMAIL
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for smtpmail files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       SMTPMAIL_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$SMTPMAIL_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the smtpmail distribution])
  dnl fi

  dnl # --with-smtpmail -> add include path
  dnl PHP_ADD_INCLUDE($SMTPMAIL_DIR/include)

  dnl # --with-smtpmail -> check for lib and symbol presence
  dnl LIBNAME=smtpmail # you may want to change this
  dnl LIBSYMBOL=smtpmail # you most likely want to change this 

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $SMTPMAIL_DIR/lib, SMTPMAIL_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_SMTPMAILLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong smtpmail lib version or lib not found])
  dnl ],[
  dnl   -L$SMTPMAIL_DIR/lib -lm
  dnl ])
  dnl
  dnl PHP_SUBST(SMTPMAIL_SHARED_LIBADD)

  PHP_NEW_EXTENSION(smtpmail, smtpmail.c, $ext_shared)
fi
