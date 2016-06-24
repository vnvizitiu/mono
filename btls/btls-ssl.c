//
//  btls-ssl.c
//  MonoBtls
//
//  Created by Martin Baulig on 14/11/15.
//  Copyright (c) 2015 Xamarin. All rights reserved.
//

#include <btls-ssl.h>
#include <btls-x509-name-list.h>

struct MonoBtlsSsl {
	MonoBtlsSslCtx *ctx;
	SSL *ssl;
};

#define debug_print(ptr,message) \
do { if (mono_btls_ssl_ctx_is_debug_enabled(ptr->ctx)) \
mono_btls_ssl_ctx_debug_printf (ptr->ctx, "%s:%d:%s(): " message, __FILE__, __LINE__, \
__func__); } while (0)

#define debug_printf(ptr,fmt, ...) \
do { if (mono_btls_ssl_ctx_is_debug_enabled(ptr->ctx)) \
mono_btls_ssl_ctx_debug_printf (ptr->ctx, "%s:%d:%s(): " fmt, __FILE__, __LINE__, \
__func__, __VA_ARGS__); } while (0)

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list (SSL *s, const CBS *cbs);

MonoBtlsSsl *
mono_btls_ssl_new (MonoBtlsSslCtx *ctx)
{
	MonoBtlsSsl *ptr;

	ptr = calloc (1, sizeof (MonoBtlsSsl));

	ptr->ctx = mono_btls_ssl_ctx_up_ref (ctx);
	ptr->ssl = SSL_new (mono_btls_ssl_ctx_get_ctx (ptr->ctx));

	SSL_set_options (ptr->ssl, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

	return ptr;
}

void
mono_btls_ssl_destroy (MonoBtlsSsl *ptr)
{
	mono_btls_ssl_close (ptr);
	if (ptr->ssl) {
		SSL_free (ptr->ssl);
		ptr->ssl = NULL;
	}
	if (ptr->ctx) {
		mono_btls_ssl_ctx_free (ptr->ctx);
		ptr->ctx = NULL;
	}
	free (ptr);
}

void
mono_btls_ssl_close (MonoBtlsSsl *ptr)
{
	;
}

void
mono_btls_ssl_set_bio (MonoBtlsSsl *ptr, BIO *bio)
{
	BIO_up_ref (bio);
	SSL_set_bio (ptr->ssl, bio, bio);
}

void
mono_btls_ssl_print_errors_cb (ERR_print_errors_callback_t callback, void *ctx)
{
	ERR_print_errors_cb (callback, ctx);
}

int
mono_btls_ssl_use_certificate (MonoBtlsSsl *ptr, X509 *x509)
{
	return SSL_use_certificate (ptr->ssl, x509);
}

int
mono_btls_ssl_use_private_key (MonoBtlsSsl *ptr, EVP_PKEY *key)
{
	return SSL_use_PrivateKey (ptr->ssl, key);
}

int
mono_btls_ssl_add_chain_certificate (MonoBtlsSsl *ptr, X509 *x509)
{
	return SSL_add1_chain_cert (ptr->ssl, x509);
}

int
mono_btls_ssl_accept (MonoBtlsSsl *ptr)
{
	return SSL_accept (ptr->ssl);
}

int
mono_btls_ssl_connect (MonoBtlsSsl *ptr)
{
	return SSL_connect (ptr->ssl);
}

int
mono_btls_ssl_handshake (MonoBtlsSsl *ptr)
{
	return SSL_do_handshake (ptr->ssl);
}

int
mono_btls_ssl_read (MonoBtlsSsl *ptr, void *buf, int count)
{
	return SSL_read (ptr->ssl, buf, count);
}

int
mono_btls_ssl_write (MonoBtlsSsl *ptr, void *buf, int count)
{
	return SSL_write (ptr->ssl, buf, count);
}

int
mono_btls_ssl_get_version (MonoBtlsSsl *ptr)
{
	return SSL_version (ptr->ssl);
}

void
mono_btls_ssl_set_min_version (MonoBtlsSsl *ptr, int version)
{
	SSL_set_min_version (ptr->ssl, version);
}

void
mono_btls_ssl_set_max_version (MonoBtlsSsl *ptr, int version)
{
	SSL_set_max_version (ptr->ssl, version);
}

int
mono_btls_ssl_get_cipher (MonoBtlsSsl *ptr)
{
	const SSL_CIPHER *cipher;

	cipher = SSL_get_current_cipher (ptr->ssl);
	if (!cipher)
		return 0;
	return (uint16_t)SSL_CIPHER_get_id (cipher);
}

int
mono_btls_ssl_set_cipher_list (MonoBtlsSsl *ptr, const char *str)
{
	return SSL_set_cipher_list(ptr->ssl, str);
}

int
mono_btls_ssl_get_ciphers (MonoBtlsSsl *ptr, uint16_t **data)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	int count, i;

	*data = NULL;

	ciphers = SSL_get_ciphers (ptr->ssl);
	if (!ciphers)
		return 0;

	count = (int)sk_SSL_CIPHER_num (ciphers);

	*data = OPENSSL_malloc (2 * count);
	if (!*data)
		return 0;

	for (i = 0; i < count; i++) {
		const SSL_CIPHER *cipher = sk_SSL_CIPHER_value (ciphers, i);
		(*data) [i] = (uint16_t) SSL_CIPHER_get_id (cipher);
	}

	return count;
}

X509 *
mono_btls_ssl_get_peer_certificate (MonoBtlsSsl *ptr)
{
	return SSL_get_peer_certificate (ptr->ssl);
}

int
mono_btls_ssl_get_error (MonoBtlsSsl *ptr, int ret_code)
{
	return SSL_get_error (ptr->ssl, ret_code);
}

const char *
mono_btls_ssl_get_servername (MonoBtlsSsl *ptr)
{
	return SSL_get_servername (ptr->ssl, TLSEXT_NAMETYPE_host_name);
}

int
mono_btls_ssl_set_servername (MonoBtlsSsl *ptr, const char *servername)
{
	return SSL_set_tlsext_host_name (ptr->ssl, servername);
}

void
mono_btls_ssl_set_client_ca_list (MonoBtlsSsl *ptr, MonoBtlsX509NameList *list)
{
	STACK_OF(X509_NAME) *stack, *copy;
	size_t i;

	stack = mono_btls_x509_name_list_peek_stack (list);
	copy = sk_X509_NAME_new_null ();

	for (i = 0; i < sk_X509_NAME_num (stack); i++) {
		X509_NAME *xname = sk_X509_NAME_value (stack, i);
		sk_X509_NAME_push (copy, X509_NAME_dup (xname));
	}

	SSL_set_client_CA_list (ptr->ssl, copy);
}

MonoBtlsX509NameList *
mono_btls_ssl_get_client_ca_list (MonoBtlsSsl *ptr)
{
	STACK_OF(X509_NAME) *stack;

	stack = SSL_get_client_CA_list (ptr->ssl);
	if (!stack)
		return NULL;

	return mono_btls_x509_name_list_new_from_stack (stack);
}

void
mono_btls_ssl_test (MonoBtlsSsl *ptr)
{
	SSL_SESSION *session;
	const char *version;
	const SSL_CIPHER *cipher;
	int test;

//	SSL_get_ciphers(<#const SSL *ssl#>)

	test = SSL_version (ptr->ssl);
	debug_printf(ptr, "TEST: %d\n", test);
	session = SSL_get_session(ptr->ssl);
	if (session) {
		version = SSL_SESSION_get_version(session);
		debug_printf (ptr, "SESSION: %p - %s\n", session, version);
	}

	cipher = SSL_get_current_cipher (ptr->ssl);
	if (cipher) {
		test = SSL_CIPHER_get_id (cipher);
		version = SSL_CIPHER_get_name (cipher);
		debug_printf (ptr, "CIPHER: %p - %x:%s\n", cipher, test, version);
	}
}
