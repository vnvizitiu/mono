//
//  btls-x509-name.h
//  MonoBtls
//
//  Created by Martin Baulig on 3/5/16.
//  Copyright © 2016 Xamarin. All rights reserved.
//

#ifndef __btls__btls_x509_name__
#define __btls__btls_x509_name__

#include <stdio.h>
#include <btls-ssl.h>

typedef enum {
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_UNKNOWN = 0,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_COUNTRY_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_ORGANIZATION_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_ORGANIZATIONAL_UNIT_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_COMMON_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_LOCALITY_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_STATE_OR_PROVINCE_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_STREET_ADDRESS,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_SERIAL_NUMBER,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_DOMAIN_COMPONENT,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_USER_ID,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_EMAIL,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_DN_QUALIFIER,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_TITLE,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_SURNAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_GIVEN_NAME,
	NATIVE_BORING_X509_NAME_ENTRY_TYPE_INITIAL
} MonoBtlsX509NameEntryType;

MonoBtlsX509Name *
mono_btls_x509_name_from_name (X509_NAME *name);

MonoBtlsX509Name *
mono_btls_x509_name_copy (X509_NAME *xn);

void
mono_btls_x509_name_free (MonoBtlsX509Name *name);

X509_NAME *
mono_btls_x509_name_peek_name (MonoBtlsX509Name *name);

MonoBtlsX509Name *
mono_btls_x509_name_from_data (const void *data, int len, int use_canon_enc);

int
mono_btls_x509_name_print_bio (MonoBtlsX509Name *name, BIO *bio);

int
mono_btls_x509_name_print_string (MonoBtlsX509Name *name, char *buffer, int size);

int
mono_btls_x509_name_get_raw_data (MonoBtlsX509Name *name, void **buffer, int use_canon_enc);

long
mono_btls_x509_name_hash (MonoBtlsX509Name *name);

MonoBtlsX509NameEntryType
mono_btls_x509_name_get_entry_type (MonoBtlsX509Name *name, int index);

int
mono_btls_x509_name_get_entry_oid (MonoBtlsX509Name *name, int index, char *buffer, int size);

int
mono_btls_x509_name_get_entry_value (MonoBtlsX509Name *name, int index, unsigned char **str);

#endif /* __btls__btls_x509_name__ */
