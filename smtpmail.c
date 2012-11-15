/*
  +----------------------------------------------------------------------+
  | PHP Version 5                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2012 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author: liminggui <linuxphp@126.com> http://blog.linuxphp.org        |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_smtpmail.h"
#include "ext/standard/file.h"
#include "ext/standard/base64.h"
/* If you declare any globals in php_smtpmail.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(smtpmail)
*/

/* True global resources - no need for thread safety here */

static int lastmessage_len;

static zend_class_entry *smtpmail_ce;

static zend_object_handlers php_smtpmail_handlers;

void php_smtpmail_error_log(php_smtpmail_object *smtpmail_obj, char *rep, char *err)/*{{{*/
{
	if (smtpmail_obj->errlog) {
		efree(smtpmail_obj->errlog);
	}
	spprintf(&(smtpmail_obj->errlog),0,rep, err);
}
/*}}}*/

char *php_smtpmail_time()/*{{{*/
{
    struct tm *ptr;
    time_t lt;
    static char str[200];
    lt=time(NULL);
    ptr=localtime(&lt);
    strftime(str,100,"%c %z",ptr);
    return str;
}
/*}}}*/

char *php_smtpmail_messageid()/*{{{*/
{
    struct timeval tp = {0};
    static char ret[100];
    int num = 0;
    int i;
	struct tm *ptr;
    time_t lt;
    static char str[200];
	
	lt=time(NULL);
	ptr=localtime(&lt);
	strftime(str,100,"%Y%m%d%H%M%S",ptr);

	if (gettimeofday(&tp, NULL)) {
        return;
    }
    srand( (unsigned)time( NULL ) ); 
    for(i=0;i<100;i++) 
    { 
        num += rand(); 
    } 
    snprintf(ret, 100, "%s.%ld%ld", str,tp.tv_usec,abs(num));
    return ret;
}
/*}}}*/

static char *php_chunk_split(char *src, int srclen, char *end, int endlen, int chunklen, int *destlen)/*{{{*/
{
	char *dest;
	char *p, *q;
	int chunks; /* complete chunks! */
	int restlen;
	int out_len;

	chunks = srclen / chunklen;
	restlen = srclen - chunks * chunklen; /* srclen % chunklen */

	if(chunks > INT_MAX - 1) {
		return NULL;
	}
	out_len = chunks + 1;
	if(endlen !=0 && out_len > INT_MAX/endlen) {
		return NULL;
	}
	out_len *= endlen;
	if(out_len > INT_MAX - srclen - 1) {
		return NULL;
	}
	out_len += srclen + 1;

	dest = safe_emalloc((int)out_len, sizeof(char), 0);

	for (p = src, q = dest; p < (src + srclen - chunklen + 1); ) {
		memcpy(q, p, chunklen);
		q += chunklen;
		memcpy(q, end, endlen);
		q += endlen;
		p += chunklen;
	}

	if (restlen) {
		memcpy(q, p, restlen);
		q += restlen;
		memcpy(q, end, endlen);
		q += endlen;
	}

	*q = '\0';
	if (destlen) {
		*destlen = q - dest;
	}

	return(dest);
}/*}}}*/

char *php_smtpmail_chunk_split(char *str)/*{{{*/
{
    char *result;
    char *end    = "\r\n";
    int endlen   = 2;
    long chunklen = 76;
    int result_len;
    int str_len=strlen(str);

    if (chunklen > str_len) {
        return str;
    }

    if (!str_len) {
        return;
    }

    result = php_chunk_split(str, str_len, end, endlen, chunklen, &result_len);

    if (result) {
        return result;
    } else {
        return;
    }
}/*}}}*/

char *php_smtpmail_readfile(char *filename)/*{{{*/
{
    char *contents;
    php_stream *stream;
    int len;
    long offset = -1;
    long maxlen = PHP_STREAM_COPY_ALL;
    zval *zcontext = NULL;
    php_stream_context *context = NULL;
	int base64_length;
	char *c = NULL;
	char *base64_str=NULL;
    
	context = php_stream_context_from_zval(zcontext, 0);

    stream = php_stream_open_wrapper_ex(filename, "rb",0 | REPORT_ERRORS,
            NULL, context);
    if (!stream) {
        return;
    }

    len = php_stream_copy_to_mem(stream, &contents, maxlen, 0);
	
    php_stream_close(stream);

    if (len > 0) {
		base64_str = (char *) php_base64_encode((unsigned char*)contents, len, &base64_length);
		spprintf(&c, 0, "%s", base64_str);
		efree(base64_str);
		efree(contents);
        return c;
    } else {
        return;
    }
}/*}}}*/

void php_smtpmail_rcpt_write(php_smtpmail_object *smtpmail_obj)/*{{{*/
{
	char *string_value = NULL;
	HashPosition pos;
	int send_length;
	char *mail_to = NULL;
	size_t line_len=0;

	zend_hash_internal_pointer_reset_ex(smtpmail_obj->rcpt, &pos);
	while (zend_hash_get_current_data_ex(smtpmail_obj->rcpt, (void **)&string_value, &pos) == SUCCESS) {
		/* mail to */
		send_length = spprintf(&mail_to, 0 , "RCPT TO: <%s>\r\n", string_value);
		php_stream_write(smtpmail_obj->stream, mail_to, send_length);
		if (smtpmail_obj->debug) {
			php_printf(mail_to);
		}

		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
		if (strncmp(smtpmail_obj->lastmessage, "250", 3)!=0) {
			php_smtpmail_error_log(smtpmail_obj,"esmtp server rcpt to is error:%s",smtpmail_obj->lastmessage);
			efree(mail_to);
			break;
		}
		efree(mail_to);
		
		/* enter to next loop */
		zend_hash_move_forward_ex(smtpmail_obj->rcpt, &pos);
	}
	
	/* clear */
	zend_hash_destroy(smtpmail_obj->rcpt);
	zend_hash_init(smtpmail_obj->rcpt, 0, NULL, NULL, 0);

}/*}}}*/

void php_smtpmail_attachments(php_smtpmail_object *smtpmail_obj)/*{{{*/
{
	char *string_value = NULL;
	HashPosition pos;
	char *string_key = NULL;
	ulong num_key;
    uint str_key_len;
	int send_length;
	char *mail_attachment = NULL;
	char *headers = NULL;
	char *tmp_attachment = NULL;

	zend_hash_internal_pointer_reset_ex(smtpmail_obj->attachments, &pos);
	while (zend_hash_get_current_data_ex(smtpmail_obj->attachments, (void **)&string_value, &pos) == SUCCESS) {
		zend_hash_get_current_key_ex(smtpmail_obj->attachments, &string_key, &str_key_len, &num_key, 0, &pos);
	
		mail_attachment = php_smtpmail_readfile(string_key);
		//file not exists
		if (mail_attachment == NULL) {
			/* enter to next loop */
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "file %s not exists", string_key);
			zend_hash_move_forward_ex(smtpmail_obj->attachments, &pos);
			continue;
		}

		send_length = spprintf(&headers, 0,  "\r\n--#BOUNDARY#\r\nContent-Type: application/octet-stream;charset=\"%s\"; name=%s\r\nContent-Disposition: attachment; filename=%s\r\nContent-Transfer-Encoding: base64\r\n\r\n",
				smtpmail_obj->charset, string_value, string_value);
		php_stream_write(smtpmail_obj->stream, headers, send_length);

		tmp_attachment = php_smtpmail_chunk_split(mail_attachment);
		efree(mail_attachment);

		send_length = spprintf(&mail_attachment, 0, "%s\r\n", tmp_attachment);

		php_stream_write(smtpmail_obj->stream, mail_attachment, send_length);

		if (smtpmail_obj->debug) {
			php_printf("%s%s",  headers, mail_attachment);
		}
		efree(headers);
		efree(mail_attachment);

		/* enter to next loop */
		zend_hash_move_forward_ex(smtpmail_obj->attachments, &pos);
	}
	
	/* clear */
	zend_hash_destroy(smtpmail_obj->attachments);
	zend_hash_init(smtpmail_obj->attachments, 0, NULL, NULL, 0);
}/*}}}*/

static void php_smtpmail_obj_dtor(void *object TSRMLS_DC) /* {{{ */
{
    php_smtpmail_object *smtpmail_obj = (php_smtpmail_object *)object;

	zend_hash_destroy(smtpmail_obj->rcpt);
	zend_hash_destroy(smtpmail_obj->attachments);
	efree(smtpmail_obj->attachments);
	efree(smtpmail_obj->rcpt);
	if (smtpmail_obj->stream != NULL) {
		php_stream_close(smtpmail_obj->stream);
		smtpmail_obj->stream = NULL;
	}
	if (smtpmail_obj->hostname != NULL) {
		efree(smtpmail_obj->hostname);
	}
	if (smtpmail_obj->delimiter != NULL) {
		efree(smtpmail_obj->delimiter);
	}
	if (smtpmail_obj->charset !=NULL) {
		efree(smtpmail_obj->charset);
	}
	if (smtpmail_obj->errlog != NULL) {
		efree(smtpmail_obj->errlog);
	}
	if (smtpmail_obj->from != NULL) {
		efree(smtpmail_obj->from);
	}
	if (smtpmail_obj->from_name != NULL) {
		efree(smtpmail_obj->from_name);
	}
	if (smtpmail_obj->to != NULL) {
		efree(smtpmail_obj->to);
	}
	if (smtpmail_obj->cc != NULL) {
		efree(smtpmail_obj->cc);
	}
	if (smtpmail_obj->bcc != NULL) {
		efree(smtpmail_obj->bcc);
	}
	efree(smtpmail_obj->lastmessage);
    zend_object_std_dtor(&smtpmail_obj->std TSRMLS_CC);
    efree(smtpmail_obj);
}
/* }}} */

static zend_object_value php_smtpmail_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
    php_smtpmail_object *smtpmail_obj;
    zend_object_value retval;

    smtpmail_obj = ecalloc(1, sizeof(*smtpmail_obj));
	smtpmail_obj->hostname = NULL;
	smtpmail_obj->from = NULL;
    smtpmail_obj->from_name = NULL;
    smtpmail_obj->to = NULL;
    smtpmail_obj->cc = NULL;
	smtpmail_obj->bcc = NULL;
    smtpmail_obj->errlog = NULL;
	smtpmail_obj->attachments = emalloc(sizeof(HashTable));
	smtpmail_obj->rcpt = emalloc(sizeof(HashTable));
	smtpmail_obj->debug = 0;

	lastmessage_len = PHP_SMTPMAIL_DEFAULT_MSG_LEN;
	smtpmail_obj->lastmessage = ecalloc(lastmessage_len+1, sizeof(char));
	
	zend_hash_init(smtpmail_obj->attachments, 0, NULL, NULL, 0);
	zend_hash_init(smtpmail_obj->rcpt, 0, NULL, NULL, 0);

    zend_object_std_init(&smtpmail_obj->std, ce TSRMLS_CC);

    retval.handle = zend_objects_store_put(smtpmail_obj, (zend_objects_store_dtor_t)zend_objects_destroy_object, php_smtpmail_obj_dtor, NULL TSRMLS_CC);
    retval.handlers = &php_smtpmail_handlers;

    return retval;
}
/* }}} */

static HashTable *php_smtpmail_get_properties(zval *object TSRMLS_DC) /* {{{ */
{
	php_smtpmail_object *c;
	char *msg;
	zval *tmp;
    HashTable *props;

	c = (php_smtpmail_object *)zend_objects_get_address(object TSRMLS_CC);

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4
    props = zend_std_get_properties(object TSRMLS_CC);
#else
    props = c->std.properties;
#endif

	if (c->hostname != NULL) {
		msg = c->hostname;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, msg, 1);
		zend_hash_update(props, "hostname", sizeof("hostname"), (void *)&tmp, sizeof(zval *), NULL);
	}

	if (c->from != NULL) {
		msg = c->from;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, msg, 1);
		zend_hash_update(props, "from", sizeof("from"), (void *)&tmp, sizeof(zval *), NULL);
	}

	if (c->errlog != NULL) {
		msg = c->errlog;
		MAKE_STD_ZVAL(tmp);
		ZVAL_STRING(tmp, msg, 1);
		zend_hash_update(props, "warning", sizeof("warning"), (void *)&tmp, sizeof(zval *), NULL);
	}

	return props;
}
/* }}} */

/* {{{ proto bool SmtpMail::__construct(string host[, int port[, int timeout[, string charset[, string delimiter[, bool debug]]]]]) */
static PHP_METHOD(SmtpMail, __construct)
{
    php_smtpmail_object *smtpmail_obj;
    char *host=NULL, *charset=PHP_SMTPMAIL_DEFAULT_CHARSET, *delimiter=PHP_SMTPMAIL_DEFAULT_DELIMITER;
    int host_len=0, charset_len=PHP_SMTPMAIL_DEFAULT_CHARSET_LEN, delimiter_len=PHP_SMTPMAIL_DEFAULT_DELIMITER_LEN;
    long port = -1;
    double timeout = PHP_SMTPMAIL_DEFAULT_TIMEOUT;
	zend_bool debug = 0;
    unsigned long conv;
    struct timeval tv;
    char *hashkey = NULL;
    php_stream *stream = NULL;
    int err=0;
    char *hostname = NULL;
    long hostname_len=0;
    char *errstr = NULL;

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);

    if (smtpmail_obj->stream) {
        return;
    }

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|ldssb", &host, &host_len, &port, &timeout, 
                &charset, &charset_len, &delimiter, &delimiter_len, &debug) == FAILURE) {
        RETURN_FALSE;
    }

    if (port > 0) {
        hostname_len = spprintf(&hostname, 0, "%s:%ld", host, port);
    } else {
        hostname_len = host_len;
        hostname = host;
    }
    
    /* prepare the timeout value for use */
    conv = (unsigned long) (timeout * 1000000.0);
    tv.tv_sec = conv / 1000000;
    tv.tv_usec = conv % 1000000;
    
    stream = php_stream_xport_create(hostname, hostname_len, REPORT_ERRORS,
            STREAM_XPORT_CLIENT | STREAM_XPORT_CONNECT, hashkey, &tv, NULL, &errstr, &err);

	spprintf(&(smtpmail_obj->hostname), 0, "%s", hostname);
    if (port > 0) {
        efree(hostname);
    }
    if (stream == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "unable to connect to %s:%ld (%s)", host, port, errstr == NULL ? "Unknown error" : errstr);
    }

    if (hashkey) {
        efree(hashkey);
    }

    if (errstr) {
        efree(errstr);
    }

	if (stream == NULL) {
		RETURN_FALSE;
	}
    
	/* set block*/
    if (php_stream_set_option(stream, PHP_STREAM_OPTION_BLOCKING, 1, NULL) == -1) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "set stream blocking faild");
        RETURN_FALSE;
    }

    smtpmail_obj->stream = stream;
	spprintf(&(smtpmail_obj->delimiter), 0, "%s", delimiter);
	spprintf(&(smtpmail_obj->charset), 0, "%s", charset);
	smtpmail_obj->debug = debug;

    RETURN_TRUE;
}
/* }}} */

/* {{{ proto bool SmtpMail::login([string user[, string pass]]) */
static PHP_METHOD(SmtpMail, login)
{
    php_smtpmail_object *smtpmail_obj;
    char *user="", *pass="";
    int user_len=0, pass_len=0;
	size_t line_len=0;
	int ret_length;
	char *ret_result = NULL;
	char *base64_str = NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ss", &user, &user_len, &pass, &pass_len) == FAILURE) {
        RETURN_FALSE;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	if (smtpmail_obj->stream == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The connection has been losted");
		RETURN_FALSE;
	}

	php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
    if (strncmp(smtpmail_obj->lastmessage, "220", 3)!=0) {
		php_smtpmail_error_log(smtpmail_obj,"esmtp server return error:%s",smtpmail_obj->lastmessage);
        RETURN_FALSE;
    }

    php_stream_write(smtpmail_obj->stream, user ? "EHLO smtpmail\r\n" : "HELO smtpmail\r\n", 15);
	if (smtpmail_obj->debug) {
		php_printf(user ? "EHLO smtpmail\r\n" : "HELO smtpmail\r\n");
	}

	php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
    if (strncmp(smtpmail_obj->lastmessage, "220", 3)!=0 && strncmp(smtpmail_obj->lastmessage,"250", 3)!=0) {
		php_smtpmail_error_log(smtpmail_obj,"esmtp server helo error:%s",smtpmail_obj->lastmessage);
        RETURN_FALSE;
    }

    while(1) {
        if(strlen(smtpmail_obj->lastmessage)==0 || strstr(smtpmail_obj->lastmessage, "-")==NULL) {
            break;
        }
		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
    }

    /*login*/
    if (user_len>0 && pass_len>0) {
        php_stream_write(smtpmail_obj->stream, "AUTH LOGIN\r\n",12);
		if (smtpmail_obj->debug) {
			php_printf("AUTH LOGIN\r\n");
		}

		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
        if (strncmp(smtpmail_obj->lastmessage, "334", 3)!=0) {
			php_smtpmail_error_log(smtpmail_obj,"esmtp server start auth error:%s",smtpmail_obj->lastmessage);
            RETURN_FALSE;
        }

		/* send username*/
		base64_str = (char *) php_base64_encode((unsigned char*)user, user_len, &ret_length);
        ret_length = spprintf(&ret_result, 0, "%s\r\n",  base64_str);
		efree(base64_str);

        php_stream_write(smtpmail_obj->stream, ret_result, ret_length);
		if (smtpmail_obj->debug) {
			php_printf(ret_result);
		}

		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
        if (strncmp(smtpmail_obj->lastmessage, "334", 3)!=0) {
			php_smtpmail_error_log(smtpmail_obj,"esmtp server put username error:%s",smtpmail_obj->lastmessage);
			goto exit_failed;
        }
		efree(ret_result);
		
		/* send password*/
		base64_str = (char *) php_base64_encode((unsigned char*)pass, pass_len, &ret_length);
        ret_length = spprintf(&ret_result, 0, "%s\r\n", base64_str);
		efree(base64_str);
        
		php_stream_write(smtpmail_obj->stream, ret_result, ret_length);
		if (smtpmail_obj->debug) {
			php_printf(ret_result);
		}

		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
        if (strncmp(smtpmail_obj->lastmessage, "235", 3)!=0) {
			php_smtpmail_error_log(smtpmail_obj,"esmtp server password is error:%s",smtpmail_obj->lastmessage);
			goto exit_failed;
        }
		efree(ret_result);
    }
	RETURN_TRUE;
exit_failed:
	if (ret_result) {
		efree(ret_result);
	}
	RETURN_FALSE;
}
/* }}}*/

/* {{{ proto bool SmtpMail::from(string from[, string name]) */
static PHP_METHOD(SmtpMail, from)
{
    php_smtpmail_object *smtpmail_obj;
    char *from="", *name="", *mail_from=NULL;
    int from_len=0, name_len=0, send_length=0, base64_length=0;
	size_t line_len=0;
	char *base64_str=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &from, &from_len, &name, &name_len) == FAILURE) {
        RETURN_FALSE;
    }
    
	smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (smtpmail_obj->stream == NULL) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The connection has been losted");
		RETURN_FALSE;
	}

	if (from_len<=0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "The from cannot be NULL");
		RETURN_FALSE;
	}

	/* mail from*/
    send_length = spprintf(&mail_from, 0 , "MAIL FROM: <%s>\r\n", from);
    php_stream_write(smtpmail_obj->stream, mail_from, send_length);
    if (smtpmail_obj->debug) {
		php_printf(mail_from);
	}

	php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
	if (strncmp(smtpmail_obj->lastmessage, "250", 3)!=0) {
		php_stream_write(smtpmail_obj->stream, mail_from, send_length);
		php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
		if (strncmp(smtpmail_obj->lastmessage, "250", 3)!=0) {
			php_smtpmail_error_log(smtpmail_obj,"esmtp server mail from is error:%s",smtpmail_obj->lastmessage);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, smtpmail_obj->errlog);
			goto exit_failed;
		}
    }

	if (smtpmail_obj->from) {
		efree(smtpmail_obj->from);
	}
	if (smtpmail_obj->from_name) {
		efree(smtpmail_obj->from_name);
	}

	spprintf(&(smtpmail_obj->from), 0, "%s", from);
    if (name_len==0) {
        spprintf(&(smtpmail_obj->from_name), 0 , "%s", from);
    } else {
		base64_str = (char *) php_base64_encode((unsigned char*)name, name_len, &base64_length);
        spprintf(&(smtpmail_obj->from_name), 0 , "=?%s?B?%s?= <%s>", smtpmail_obj->charset, base64_str, from);
		efree(base64_str);
    }

	efree(mail_from);

	RETURN_TRUE;
exit_failed:
	if (mail_from) {
		efree(mail_from);
	}
	RETURN_FALSE;
}
/* }}}*/

/* {{{ proto void SmtpMail::to(string to[, string name]) */
static PHP_METHOD(SmtpMail, to)
{
    php_smtpmail_object *smtpmail_obj;
    char *to="", *name="";
    int to_len=0, name_len=0, base64_length=0;
	char *base64_str=NULL;
	char *tmp_to=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &to, &to_len, &name, &name_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (to_len <= 0) {
        RETURN_FALSE;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	base64_str =  (char *) php_base64_encode((unsigned char*)name, name_len, &base64_length);
	if (smtpmail_obj->to) {
		spprintf(&tmp_to, 0 , "%s, =?%s?B?%s?= <%s>", smtpmail_obj->to, smtpmail_obj->charset, base64_str, to);	
		efree(smtpmail_obj->to);
		smtpmail_obj->to = tmp_to;
	} else {
		spprintf(&(smtpmail_obj->to), 0 , "=?%s?B?%s?= <%s>",  smtpmail_obj->charset, base64_str, to);
	}
   
	zend_hash_add(smtpmail_obj->rcpt, to, to_len+1, to, to_len+1, NULL);

	efree(base64_str);
}
/* }}}*/

/* {{{ proto void SmtpMail::cc(string cc[, string name]) */
static PHP_METHOD(SmtpMail, cc)
{
    php_smtpmail_object *smtpmail_obj;
    char *cc="", *name="";
    int cc_len=0, name_len=0, base64_length=0;
	char *base64_str=NULL;
	char *tmp_cc=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &cc, &cc_len, &name, &name_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (cc_len <= 0) {
        RETURN_FALSE;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);

	base64_str =  (char *) php_base64_encode((unsigned char*)name, name_len, &base64_length);
	if (smtpmail_obj->cc) {
		spprintf(&tmp_cc, 0 , "%s, =?%s?B?%s?= <%s>", smtpmail_obj->cc, smtpmail_obj->charset, base64_str, cc);
		efree(smtpmail_obj->cc);
		smtpmail_obj->cc = tmp_cc;
	} else {
		spprintf(&(smtpmail_obj->cc), 0 , "=?%s?B?%s?= <%s>", smtpmail_obj->charset, base64_str, cc);
	}

	zend_hash_add(smtpmail_obj->rcpt, cc, cc_len+1, cc, cc_len+1, NULL);
	efree(base64_str);
}
/* }}}*/

/* {{{ proto void SmtpMail::bcc(string bcc[, string name]) */
static PHP_METHOD(SmtpMail, bcc)
{
    php_smtpmail_object *smtpmail_obj;
    char *bcc="", *name="";
    int bcc_len=0, name_len=0, base64_length=0;
	char *base64_str=NULL;
	char *tmp_bcc=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s", &bcc, &bcc_len, &name, &name_len) == FAILURE) {
        RETURN_FALSE;
    }
 
    if (bcc_len <= 0) {
        RETURN_FALSE;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);
	
	base64_str =  (char *) php_base64_encode((unsigned char*)name, name_len, &base64_length);
	if (smtpmail_obj->bcc) {
		spprintf(&tmp_bcc, 0 , "%s, =?%s?B?%s?= <%s>", smtpmail_obj->bcc, smtpmail_obj->charset, base64_str, bcc);
		efree(smtpmail_obj->bcc);
		smtpmail_obj->bcc = tmp_bcc;
	} else {
		spprintf(&(smtpmail_obj->bcc), 0 , "=?%s?B?%s?= <%s>",  smtpmail_obj->charset, base64_str, bcc);
	}

	zend_hash_add(smtpmail_obj->rcpt, bcc, bcc_len+1, bcc, bcc_len+1, NULL);

	efree(base64_str);
}
/* }}}*/

/* {{{ proto void SmtpMail::attachment(string file_path, string file_name) */
static PHP_METHOD(SmtpMail, attachment)
{
    php_smtpmail_object *smtpmail_obj;
    char *file="", *file_name="";
    int file_len=0, file_name_len=0, base64_length=0;
	char *base64_str=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &file, &file_len, &file_name, &file_name_len) == FAILURE) {
        RETURN_FALSE;
    }
 
    if (file_len <= 0) {
        RETURN_FALSE;
    }

    if (file_name_len <= 0) {
        file_name = file;
        file_name_len = file_len;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);

	base64_str =  (char *) php_base64_encode((unsigned char*)file_name, file_name_len, &base64_length);
	file_name_len = spprintf(&file_name, 0 , "=?%s?B?%s?=", smtpmail_obj->charset, base64_str);
	
	zend_hash_add(smtpmail_obj->attachments, file, file_len+1, file_name, file_name_len+1, NULL);

	efree(base64_str);
	efree(file_name);
}
/* }}}*/

/* {{{ proto bool SmtpMail::send(string subject, string body) */
static PHP_METHOD(SmtpMail, send)
{
    php_smtpmail_object *smtpmail_obj;
    char *subject = NULL, *body = NULL;
    int subject_len=0, body_len=0;
    char *mail_from = NULL, *mail_to=NULL, *mail_cc="",*mail_bcc="", *mail_subject=NULL, *mail_body=NULL, *headers=NULL;
    char *date_str = NULL;
    int send_length = 0,  base64_length=0;
    char *send_log=NULL;
	size_t line_len=0;
	char *base64_str = NULL;
	char *tmp_body=NULL;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &subject, &subject_len, &body, &body_len) == FAILURE) {
        RETURN_FALSE;
    }

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);
   
    if (smtpmail_obj->stream == NULL) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "The connection has been losted");
        RETURN_FALSE;
    }

	if (smtpmail_obj->from==NULL || strlen(smtpmail_obj->from) == 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Please first use $smtpmail->from method to set mail from");
		RETURN_FALSE;
	}

	if (smtpmail_obj->to==NULL || strlen(smtpmail_obj->to) == 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Please first use $smtpmail->to method to set mail to");
		RETURN_FALSE;
	}

	/*rcpt send*/
	php_smtpmail_rcpt_write(smtpmail_obj);

    php_stream_write(smtpmail_obj->stream, "DATA\r\n",6);
	php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
    if (strncmp(smtpmail_obj->lastmessage, "354", 3)!=0) {
		php_smtpmail_error_log(smtpmail_obj,"esmtp server data is error:%s",smtpmail_obj->lastmessage);
        RETURN_FALSE;
    }
    
    send_length = spprintf(&mail_from, 0 , "From: %s\r\n", smtpmail_obj->from_name);
    php_stream_write(smtpmail_obj->stream, mail_from, send_length);
    
	send_length = spprintf(&mail_to, 0 , "To: %s\r\n", smtpmail_obj->to);
    php_stream_write(smtpmail_obj->stream, mail_to, send_length);

    if (smtpmail_obj->debug) {
        php_printf("%s%s%s", "DATA\r\n",mail_from, mail_to);
    }
	efree(mail_from);
	efree(mail_to);

    if (smtpmail_obj->cc!=NULL && strlen(smtpmail_obj->cc)>0) {
        send_length = spprintf(&mail_cc, 0 , "Cc: %s\r\n", smtpmail_obj->cc);
        php_stream_write(smtpmail_obj->stream, mail_cc, send_length);
        if (smtpmail_obj->debug) {
            php_printf("%s", mail_cc);
        } 
		efree(mail_cc);
    }

	if (smtpmail_obj->bcc!=NULL && strlen(smtpmail_obj->bcc)>0) {
        send_length = spprintf(&mail_bcc, 0 , "Bcc: %s\r\n", smtpmail_obj->bcc);
        php_stream_write(smtpmail_obj->stream, mail_bcc, send_length);
        if (smtpmail_obj->debug) {
            php_printf("%s", mail_bcc);
        } 
		efree(mail_bcc);
    }
	
	send_length = spprintf(&date_str,0, "Date: %s\r\n", php_smtpmail_time());
    php_stream_write(smtpmail_obj->stream, date_str, send_length);
	
	base64_str = (char *) php_base64_encode((unsigned char*)subject,strlen(subject), &base64_length);
    send_length = spprintf(&mail_subject, 0 , "Subject: =?%s?B?%s?=\r\n", smtpmail_obj->charset, base64_str);

    php_stream_write(smtpmail_obj->stream, mail_subject, send_length);
	
    send_length = spprintf(&headers, 0, "X-Priority: 3%sX-Mailer: SmtpMail %s%sMIME-Version: 1.0%sMessage-ID: <%s.%s>%sContent-type: multipart/mixed;boundary=\"#BOUNDARY#\"\r\n\r\nThis is a multi-part message in MIME format.\r\n\r\n",
            smtpmail_obj->delimiter, 
            PHP_SMTPMAIL_VERSION, smtpmail_obj->delimiter, 
			smtpmail_obj->delimiter,
            php_smtpmail_messageid(),smtpmail_obj->from,smtpmail_obj->delimiter
            );
    php_stream_write(smtpmail_obj->stream, headers,send_length);
    
    if (smtpmail_obj->debug) {
        php_printf("%s%s%s", date_str, mail_subject, headers);
    }
	efree(base64_str);
	efree(date_str);
	efree(mail_subject);
	efree(headers);

	/*headers*/
    send_length = spprintf(&headers, 0 ,"--#BOUNDARY#%sContent-type: text/html; charset=%s%sContent-Transfer-Encoding: base64\r\n\r\n",
             smtpmail_obj->delimiter, smtpmail_obj->charset, smtpmail_obj->delimiter);
    php_stream_write(smtpmail_obj->stream, headers, send_length);
    
	/*RFC 2045*/
    base64_str = (char *) php_base64_encode((unsigned char*)body, body_len, &base64_length);
	spprintf(&body, 0 , "%s", base64_str);
	tmp_body = php_smtpmail_chunk_split(body);

    send_length = spprintf(&mail_body, 0 , "%s\r\n", tmp_body);
    php_stream_write(smtpmail_obj->stream, mail_body,send_length);
    if (smtpmail_obj->debug) {
        php_printf("%s%s", headers, mail_body);
    }
	efree(base64_str);
	efree(headers);
	efree(body);
	efree(mail_body);
	
	/*attachment*/
    if (zend_hash_num_elements(smtpmail_obj->attachments) > 0) {
		php_smtpmail_attachments(smtpmail_obj);
    }

	/*end #BOUNDARY#*/
	php_stream_write(smtpmail_obj->stream, "--#BOUNDARY#--\r\n", 16);
    /*send*/
    php_stream_write(smtpmail_obj->stream, ".\r\n", 3);

	php_stream_get_line(smtpmail_obj->stream, smtpmail_obj->lastmessage, lastmessage_len, &line_len);
    if (strncmp(smtpmail_obj->lastmessage,"250", 3)!=0) {
		php_smtpmail_error_log(smtpmail_obj,"esmtp server send is error:%s",smtpmail_obj->lastmessage);
        RETURN_FALSE;
    }

	/* re init */
	if (smtpmail_obj->to) {
		efree(smtpmail_obj->to);
		smtpmail_obj->to = NULL;
	}
	if (smtpmail_obj->cc) {
		efree(smtpmail_obj->cc);
		smtpmail_obj->cc = NULL;
	}
	if (smtpmail_obj->bcc) {
		efree(smtpmail_obj->bcc);
		smtpmail_obj->bcc = NULL;
	}

    if (smtpmail_obj->debug) {
        php_printf("--#BOUNDARY#--\r\n.\r\n");
    }

	RETURN_TRUE;
}
/* }}}*/

/* {{{ proto string SmtpMail::error() */
static PHP_METHOD(SmtpMail, error)
{
    php_smtpmail_object *smtpmail_obj;

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);

	if (smtpmail_obj->errlog) {
		RETURN_STRING(smtpmail_obj->errlog, 1);
	}
}
/* }}}*/

/* {{{ proto bool SmtpMail::close() */
static PHP_METHOD(SmtpMail, close)
{
    php_smtpmail_object *smtpmail_obj;

    smtpmail_obj = (php_smtpmail_object *)zend_object_store_get_object(getThis() TSRMLS_CC);
    
    if (smtpmail_obj->stream == NULL) {
        RETURN_FALSE;
    }
    php_stream_write(smtpmail_obj->stream, "QUIT\r\n",6);

    RETURN_TRUE;

}
/* }}}*/

/* {{{ arginfo */
ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_login, 0, 0, 0)
    ZEND_ARG_INFO(0, user)
    ZEND_ARG_INFO(0, pass)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_from, 0, 0, 1)
    ZEND_ARG_INFO(0, mail)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_to, 0, 0, 1)
    ZEND_ARG_INFO(0, mail)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()
    
ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_cc, 0, 0, 1)
    ZEND_ARG_INFO(0, mail)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_bcc, 0, 0, 1)
    ZEND_ARG_INFO(0, mail)
    ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_attachment, 0, 0, 1)
    ZEND_ARG_INFO(0, file)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_send, 0, 0, 2)
    ZEND_ARG_INFO(0, subject)
    ZEND_ARG_INFO(0, body)
    ZEND_ARG_INFO(0, log)
ZEND_END_ARG_INFO()   

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_error, 0, 0, 0)
ZEND_END_ARG_INFO()   

ZEND_BEGIN_ARG_INFO_EX(arginfo_smtpmail_close, 0, 0, 0)
ZEND_END_ARG_INFO()   
/* }}} */

static zend_function_entry smtpmail_methods[] = {/*{{{*/
    PHP_ME(SmtpMail, __construct,   NULL,                           ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
    PHP_ME(SmtpMail, login,         arginfo_smtpmail_login,         ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, from,          arginfo_smtpmail_from,          ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, to,            arginfo_smtpmail_to,            ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, cc,            arginfo_smtpmail_cc,            ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, bcc,           arginfo_smtpmail_bcc,           ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, attachment,    arginfo_smtpmail_attachment,    ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, send,          arginfo_smtpmail_send,          ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, error,         arginfo_smtpmail_error,         ZEND_ACC_PUBLIC)
    PHP_ME(SmtpMail, close,         arginfo_smtpmail_close,         ZEND_ACC_PUBLIC)
    {NULL, NULL, NULL}
};/*}}}*/

static zend_function_entry smtpmail_functions[] = {/*{{{*/
    {NULL, NULL, NULL}
};/*}}}*/

/* {{{ smtpmail_module_entry
 */
zend_module_entry smtpmail_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"smtpmail",
	smtpmail_functions,
	PHP_MINIT(smtpmail),
	PHP_MSHUTDOWN(smtpmail),
	NULL,		/* Replace with NULL if there's nothing to do at request start */
	NULL,	/* Replace with NULL if there's nothing to do at request end */
	PHP_MINFO(smtpmail),
#if ZEND_MODULE_API_NO >= 20010901
	PHP_SMTPMAIL_VERSION, /* version number of extension */
#endif
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_SMTPMAIL
ZEND_GET_MODULE(smtpmail)
#endif

/* {{{ PHP_INI
 */
/* Remove comments and fill if you need to have entries in php.ini
PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("smtpmail.global_value",      "42", PHP_INI_ALL, OnUpdateLong, global_value, zend_smtpmail_globals, smtpmail_globals)
    STD_PHP_INI_ENTRY("smtpmail.global_string", "foobar", PHP_INI_ALL, OnUpdateString, global_string, zend_smtpmail_globals, smtpmail_globals)
PHP_INI_END()
*/
/* }}} */

/* {{{ php_smtpmail_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_smtpmail_init_globals(zend_smtpmail_globals *smtpmail_globals)
{
	smtpmail_globals->global_value = 0;
	smtpmail_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(smtpmail)
{
	/* If you have INI entries, uncomment these lines 
	REGISTER_INI_ENTRIES();
	*/
    zend_class_entry ce;

    memcpy(&php_smtpmail_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));

	php_smtpmail_handlers.get_properties = php_smtpmail_get_properties;

    INIT_CLASS_ENTRY(ce, "SmtpMail", smtpmail_methods);
    smtpmail_ce = zend_register_internal_class(&ce TSRMLS_CC);
    smtpmail_ce->create_object = php_smtpmail_new;

	
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(smtpmail)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(smtpmail)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "smtpmail support", "enabled");
	php_info_print_table_header(2, "Version", PHP_SMTPMAIL_VERSION);
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */


/* The previous line is meant for vim and emacs, so it can correctly fold and 
   unfold functions in source code. See the corresponding marks just before 
   function definition, where the functions purpose is also documented. Please 
   follow this convention for the convenience of others editing your code.
*/


/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
