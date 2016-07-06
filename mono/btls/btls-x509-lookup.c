//
//  btls-x509-lookup.c
//  MonoBtls
//
//  Created by Martin Baulig on 3/6/16.
//  Copyright © 2016 Xamarin. All rights reserved.
//

#include <btls-x509-lookup.h>

struct MonoBtlsX509Lookup {
	X509_LOOKUP *lookup;
	MonoBtlsX509Store *store;
	MonoBtlsX509LookupMethod *method;
	CRYPTO_refcount_t references;
};

MonoBtlsX509Lookup *
mono_btls_x509_lookup_new (MonoBtlsX509Store *store, MonoBtlsX509LookupMethod *method)
{
	MonoBtlsX509Lookup *lookup;
	X509_LOOKUP *store_lookup;

	lookup = OPENSSL_malloc (sizeof(MonoBtlsX509Lookup));
	if (!lookup)
		return NULL;

	store_lookup = X509_STORE_add_lookup (mono_btls_x509_store_peek_store (store), mono_btls_x509_lookup_method_peek_method (method));
	if (!store_lookup)
		return NULL;

	memset (lookup, 0, sizeof(MonoBtlsX509Lookup));
	lookup->method = mono_btls_x509_lookup_method_up_ref (method);
	lookup->store = mono_btls_x509_store_up_ref (store);
	lookup->lookup = store_lookup;
	lookup->references = 1;
	return lookup;
}

int
mono_btls_x509_lookup_load_file (MonoBtlsX509Lookup *lookup, const char *file, MonoBtlsX509FileType type)
{
	return X509_LOOKUP_load_file (lookup->lookup, file, type);
}

int
mono_btls_x509_lookup_add_dir (MonoBtlsX509Lookup *lookup, const char *dir, MonoBtlsX509FileType type)
{
	return X509_LOOKUP_add_dir (lookup->lookup, dir, type);
}

MonoBtlsX509Lookup *
mono_btls_x509_lookup_up_ref (MonoBtlsX509Lookup *lookup)
{
	CRYPTO_refcount_inc (&lookup->references);
	return lookup;
}

int
mono_btls_x509_lookup_free (MonoBtlsX509Lookup *lookup)
{
	if (!CRYPTO_refcount_dec_and_test_zero (&lookup->references))
		return 0;

	if (lookup->lookup) {
		X509_LOOKUP_free (lookup->lookup);
		lookup = NULL;
	}
	OPENSSL_free (lookup);
	return 1;
}

int
mono_btls_x509_lookup_init (MonoBtlsX509Lookup *lookup)
{
	return X509_LOOKUP_init (lookup->lookup);
}

int
mono_btls_x509_lookup_shutdown (MonoBtlsX509Lookup *lookup)
{
	return X509_LOOKUP_shutdown (lookup->lookup);
}

X509 *
mono_btls_x509_lookup_by_subject (MonoBtlsX509Lookup *lookup, MonoBtlsX509Name *name)
{
	X509_OBJECT obj;
	X509 *x509;
	int ret;

	ret = X509_LOOKUP_by_subject (lookup->lookup, X509_LU_X509, mono_btls_x509_name_peek_name (name), &obj);
	if (ret != X509_LU_X509) {
		X509_OBJECT_free_contents (&obj);
		return NULL;
	}

	x509 = X509_up_ref (obj.data.x509);
	return x509;
}

X509 *
mono_btls_x509_lookup_by_fingerprint (MonoBtlsX509Lookup *lookup, unsigned char *bytes, int len)
{
	X509_OBJECT obj;
	X509 *x509;
	int ret;

	ret = X509_LOOKUP_by_fingerprint (lookup->lookup, X509_LU_X509, bytes, len, &obj);
	if (ret != X509_LU_X509) {
		X509_OBJECT_free_contents (&obj);
		return NULL;
	}

	x509 = X509_up_ref (obj.data.x509);
	return x509;
}
