//
//  btls-x509-lookup-method.c
//  MonoBtls
//
//  Created by Martin Baulig on 3/6/16.
//  Copyright © 2016 Xamarin. All rights reserved.
//

#include <btls-x509-lookup-method.h>
#include <btls-x509-lookup.h>

struct MonoBtlsX509LookupMethod {
	X509_LOOKUP_METHOD mono_method;
	X509_LOOKUP_METHOD *method;
	int using_mono_method;
	const void *instance;
	MonoBtlsLookupMethod_Init new_item_func;
	MonoBtlsLookupMethod_NewItem init_func;
	MonoBtlsLookupMethod_Shutdown shutdown_func;
	MonoBtlsLookupMethod_BySubject by_subject_func;
	MonoBtlsLookupMethod_ByFingerPrint by_fingerprint_func;
	CRYPTO_refcount_t references;
};

static int
mono_new_item (X509_LOOKUP *ctx)
{
	MonoBtlsX509LookupMethod *method = (MonoBtlsX509LookupMethod *)ctx->method;
	int ret = 1;

	fprintf (stderr, "mono_new_item(): %p - %p\n", ctx, method);
	if (method->new_item_func)
		ret = (*method->new_item_func) (method->instance);
	fprintf (stderr, "mono_new_item() #1: %d\n", ret);
	return 1;
}

static int
mono_init (X509_LOOKUP *ctx)
{
	MonoBtlsX509LookupMethod *method = (MonoBtlsX509LookupMethod *)ctx->method;
	int ret = 1;

	fprintf (stderr, "mono_init(): %p - %p\n", ctx, method);
	if (method->init_func)
		ret = (*method->init_func) (method->instance);
	fprintf (stderr, "mono_init() #1: %d\n", ret);
	return 1;
}

static int
mono_ctrl (X509_LOOKUP *ctx, int cmd, const char *argp, long argl, char **ret)
{
	fprintf (stderr, "mono_ctrl(): %p\n", ctx);
	return 0;
}

static void
mono_free (X509_LOOKUP *ctx)
{
	MonoBtlsX509LookupMethod *method = (MonoBtlsX509LookupMethod *)ctx->method;

	fprintf (stderr, "mono_free(): %p - %p\n", ctx, method);
	mono_btls_x509_lookup_method_free (method);
}

static int
mono_get_by_subject (X509_LOOKUP *ctx, int type, X509_NAME *name, X509_OBJECT *obj_ret)
{
	MonoBtlsX509LookupMethod *method = (MonoBtlsX509LookupMethod *)ctx->method;
	MonoBtlsX509Name *name_obj;
	X509 *x509;
	int ret;

	fprintf (stderr, "mono_get_by_subject(): %p - %p\n", ctx, method);

	if (!method->by_subject_func)
		return 0;
	if (type != X509_LU_X509)
		return 0;

	name_obj = mono_btls_x509_name_from_name (name);
	x509 = NULL;

	ret = (* method->by_subject_func) (method->instance, name_obj, &x509);
	mono_btls_x509_name_free (name_obj);

	if (!ret) {
		if (x509)
			X509_free(x509);
		return 0;
	}

	obj_ret->type = X509_LU_X509;
	obj_ret->data.x509 = x509;
	return 1;
}

static int
mono_get_by_fingerprint (X509_LOOKUP *ctx, int type, unsigned char *bytes, int len, X509_OBJECT *obj_ret)
{
	MonoBtlsX509LookupMethod *method = (MonoBtlsX509LookupMethod *)ctx->method;
	X509 *x509;
	int ret;

	fprintf (stderr, "mono_get_by_fingerprint(): %p - %p\n", ctx, method);

	if (!method->by_fingerprint_func)
		return 0;
	if (type != X509_LU_X509)
		return 0;

	x509 = NULL;

	ret = (* method->by_fingerprint_func) (method->instance, bytes, len, &x509);

	if (!ret) {
		if (x509)
			X509_free(x509);
		return 0;
	}

	obj_ret->type = X509_LU_X509;
	obj_ret->data.x509 = x509;
	return 1;

}

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_mono_new (void)
{
	MonoBtlsX509LookupMethod *method;

	method = OPENSSL_malloc (sizeof (MonoBtlsX509LookupMethod));
	if (!method)
		return NULL;

	memset (method, 0, sizeof (MonoBtlsX509LookupMethod));
	method->mono_method.name = "Mono";
	method->mono_method.init = mono_init;
	method->mono_method.new_item = mono_new_item;
	method->mono_method.get_by_subject = mono_get_by_subject;
	method->mono_method.get_by_fingerprint = mono_get_by_fingerprint;
	method->mono_method.ctrl = mono_ctrl;
	method->mono_method.free = mono_free;
	method->method = (X509_LOOKUP_METHOD *)method;
	method->using_mono_method = 1;
	method->references = 1;
	return method;
}

void
mono_btls_x509_lookup_method_mono_init (MonoBtlsX509LookupMethod *method,
					    const void *instance,
					    MonoBtlsLookupMethod_NewItem new_item_func,
					    MonoBtlsLookupMethod_Init init_func,
					    MonoBtlsLookupMethod_Shutdown shutdown_func)
{
	method->instance = instance;
	method->new_item_func = new_item_func;
	method->init_func = init_func;
	method->shutdown_func = shutdown_func;
}

void
mono_btls_x509_lookup_method_mono_set_by_subject_func (MonoBtlsX509LookupMethod *method,
							   MonoBtlsLookupMethod_BySubject by_subject_func)
{
	method->by_subject_func = by_subject_func;
}

void
mono_btls_x509_lookup_method_mono_set_by_fingerprint_func (MonoBtlsX509LookupMethod *method,
							       MonoBtlsLookupMethod_ByFingerPrint by_fingerprint)
{
	method->by_fingerprint_func = by_fingerprint;
}

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_new (X509_LOOKUP_METHOD *m)
{
	MonoBtlsX509LookupMethod *method;

	method = OPENSSL_malloc (sizeof(MonoBtlsX509LookupMethod));
	if (!method)
		return NULL;

	memset (method, 0, sizeof(MonoBtlsX509LookupMethod));
	method->method = m;
	method->references = 1;
	return method;
}

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_by_file (void)
{
	return mono_btls_x509_lookup_method_new (X509_LOOKUP_file ());
}

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_by_hash_dir (void)
{
	return mono_btls_x509_lookup_method_new (X509_LOOKUP_hash_dir ());
}

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_up_ref (MonoBtlsX509LookupMethod *method)
{
	CRYPTO_refcount_inc (&method->references);
	return method;
}

int
mono_btls_x509_lookup_method_free (MonoBtlsX509LookupMethod *method)
{
	if (!CRYPTO_refcount_dec_and_test_zero (&method->references))
		return 0;

	OPENSSL_free (method);
	return 1;
}

X509_LOOKUP_METHOD *
mono_btls_x509_lookup_method_peek_method (MonoBtlsX509LookupMethod *method)
{
	return method->method;
}

