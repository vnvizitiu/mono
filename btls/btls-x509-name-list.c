//
//  btls-x509-name-list.c
//  MonoBtls
//
//  Created by Martin Baulig on 14/11/15.
//  Copyright (c) 2015 Xamarin. All rights reserved.
//

#include <btls-x509-name-list.h>

struct MonoBtlsX509NameList {
	STACK_OF(X509_NAME) *stack;
};

MonoBtlsX509NameList *
mono_btls_x509_name_list_new (void)
{
	MonoBtlsX509NameList *ptr;

	ptr = OPENSSL_malloc (sizeof (MonoBtlsX509NameList));
	if (!ptr)
		return NULL;

	memset (ptr, 0, sizeof (MonoBtlsX509NameList));
	ptr->stack = sk_X509_NAME_new_null ();
	return ptr;
}

MonoBtlsX509NameList *
mono_btls_x509_name_list_new_from_stack (const STACK_OF(X509_NAME) *stack)
{
	MonoBtlsX509NameList *ptr;
	size_t i;

	if (!stack)
		return NULL;

	ptr = mono_btls_x509_name_list_new ();
	if (!ptr)
		return NULL;

	for (i = 0; i < sk_X509_NAME_num (stack); i++) {
		X509_NAME *xname = sk_X509_NAME_value (stack, i);
		sk_X509_NAME_push (ptr->stack, X509_NAME_dup (xname));
	}

	return ptr;
}

STACK_OF(X509_NAME) *
mono_btls_x509_name_list_peek_stack (MonoBtlsX509NameList *ptr)
{
	return ptr->stack;
}

int
mono_btls_x509_name_list_get_count (MonoBtlsX509NameList *ptr)
{
	return sk_X509_NAME_num (ptr->stack);
}

MonoBtlsX509Name *
mono_btls_x509_name_list_get_item (MonoBtlsX509NameList *ptr, int index)
{
	X509_NAME *xname;

	if (index < 0 || (size_t)index >= sk_X509_NAME_num (ptr->stack))
		return NULL;

	xname = sk_X509_NAME_value (ptr->stack, index);
	return mono_btls_x509_name_copy (xname);
}

void
mono_btls_x509_name_list_add (MonoBtlsX509NameList *ptr, MonoBtlsX509Name *name)
{
	X509_NAME *xname;

	xname = mono_btls_x509_name_peek_name (name);
	sk_X509_NAME_push (ptr->stack, X509_NAME_dup (xname));
}

void
mono_btls_x509_name_list_free (MonoBtlsX509NameList *ptr)
{
	if (ptr->stack) {
		sk_X509_NAME_free (ptr->stack);
		ptr->stack = NULL;
	}
	OPENSSL_free (ptr);
}
