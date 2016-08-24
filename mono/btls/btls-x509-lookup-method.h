//
//  btls-x509-lookup-method.h
//  MonoBtls
//
//  Created by Martin Baulig on 3/3/16.
//  Copyright © 2016 Xamarin. All rights reserved.
//

#ifndef __btls__btls_x509_lookup_method__
#define __btls__btls_x509_lookup_method__

#include <stdio.h>
#include <btls-ssl.h>
#include <btls-x509.h>

typedef int (* MonoBtlsLookupMethod_NewItem) (const void *instance);
typedef int (* MonoBtlsLookupMethod_Init) (const void *instance);
typedef int (* MonoBtlsLookupMethod_Shutdown) (const void *instance);
typedef int (* MonoBtlsLookupMethod_BySubject) (const void *instance, MonoBtlsX509Name *name, X509 **ret);

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_mono_new (void);

void
mono_btls_x509_lookup_method_mono_init (MonoBtlsX509LookupMethod *method, const void *instance,
					MonoBtlsLookupMethod_BySubject by_subject_func);

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_new (X509_LOOKUP_METHOD *method);

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_by_file (void);

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_by_hash_dir (void);

MonoBtlsX509LookupMethod *
mono_btls_x509_lookup_method_up_ref (MonoBtlsX509LookupMethod *method);

int
mono_btls_x509_lookup_method_free (MonoBtlsX509LookupMethod *method);

X509_LOOKUP_METHOD *
mono_btls_x509_lookup_method_peek_method (MonoBtlsX509LookupMethod *method);

#endif /* defined(__btls__btls_x509_lookup_method__) */

