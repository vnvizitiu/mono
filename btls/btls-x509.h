//
//  btls-x509.h
//  MonoBtls
//
//  Created by Martin Baulig on 14/11/15.
//  Copyright (c) 2015 Xamarin. All rights reserved.
//

#ifndef __btls__btls_x509__
#define __btls__btls_x509__

#include <stdio.h>
#include <btls-ssl.h>
#include <btls-x509-name.h>

typedef enum {
	NATIVE_BORING_X509_FORMAT_DER = 1,
	NATIVE_BORING_X509_FORMAT_PEM = 2
} MonoBtlsX509Format;

typedef enum {
	NATIVE_BORING_x509_FILE_TYPE_PEM = 1,		// X509_FILETYPE_PEM
	NATIVE_BORING_x509_FILE_TYPE_ASN1 = 2,		// X509_FILETYPE_ASN1
	NATIVE_BORING_x509_FILE_TYPE_DEFAULT = 3,	// X509_FILETYPE_DEFAULT
} MonoBtlsX509FileType;

typedef enum {
	NATIVE_BORING_X509_PURPOSE_SSL_CLIENT		= 1,
	NATIVE_BORING_X509_PURPOSE_SSL_SERVER		= 2,
	NATIVE_BORING_X509_PURPOSE_NS_SSL_SERVER	= 3,
	NATIVE_BORING_X509_PURPOSE_SMIME_SIGN		= 4,
	NATIVE_BORING_X509_PURPOSE_SMIME_ENCRYPT	= 5,
	NATIVE_BORING_X509_PURPOSE_CRL_SIGN		= 6,
	NATIVE_BORING_X509_PURPOSE_ANY			= 7,
	NATIVE_BORING_X509_PURPOSE_OCSP_HELPER		= 8,
	NATIVE_BORING_X509_PURPOSE_TIMESTAMP_SIGN	= 9,
} MonoBtlsX509Purpose;

X509 *
mono_btls_x509_from_data (const void *buf, int len, MonoBtlsX509Format format);

X509 *
mono_btls_x509_up_ref (X509 *x509);

void
mono_btls_x509_free (X509 *x509);

MonoBtlsX509Name *
mono_btls_x509_get_subject_name (X509 *x509);

MonoBtlsX509Name *
mono_btls_x509_get_issuer_name (X509 *x509);

int
mono_btls_x509_get_subject_name_string (X509 *name, char *buffer, int size);

int
mono_btls_x509_get_issuer_name_string (X509 *name, char *buffer, int size);

int
mono_btls_x509_get_raw_data (X509 *x509, BIO *bio);

int
mono_btls_x509_cmp (const X509 *a, const X509 *b);

int
mono_btls_x509_get_hash (X509 *x509, const void **data);

long
mono_btls_x509_get_not_before (X509 *x509);

long
mono_btls_x509_get_not_after (X509 *x509);

int
mono_btls_x509_get_public_key (X509 *x509, BIO *bio);

int
mono_btls_x509_get_serial_number (X509 *x509, char *buffer, int size, int mono_style);

int
mono_btls_x509_get_public_key_algorithm (X509 *x509, char *buffer, int size);

int
mono_btls_x509_get_version (X509 *x509);

int
mono_btls_x509_get_signature_algorithm (X509 *x509, char *buffer, int size);

int
mono_btls_x509_get_public_key_asn1 (X509 *x509, char *out_oid, int oid_len, uint8_t **buffer, int *size);

EVP_PKEY *
mono_btls_x509_get_pubkey (X509 *x509);

#endif /* defined(__btls__btls_x509__) */
