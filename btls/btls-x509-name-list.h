//
//  btls-x509-name-list.h
//  MonoBtls
//
//  Created by Martin Baulig on 14/11/15.
//  Copyright (c) 2015 Xamarin. All rights reserved.
//

#ifndef __btls__btls_x509_name_list__
#define __btls__btls_x509_name_list__

#include <btls-ssl-ctx.h>
#include <btls-x509-name.h>

MonoBtlsX509NameList *
mono_btls_x509_name_list_new (void);

MonoBtlsX509NameList *
mono_btls_x509_name_list_new_from_stack (const STACK_OF(X509_NAME) *stack);

int
mono_btls_x509_name_list_get_count (MonoBtlsX509NameList *ptr);

STACK_OF(X509_NAME) *
mono_btls_x509_name_list_peek_stack (MonoBtlsX509NameList *ptr);

MonoBtlsX509Name *
mono_btls_x509_name_list_get_item (MonoBtlsX509NameList *ptr, int index);

void
mono_btls_x509_name_list_add (MonoBtlsX509NameList *ptr, MonoBtlsX509Name *name);

void
mono_btls_x509_name_list_free (MonoBtlsX509NameList *ptr);

#endif /* defined(__btls__btls_x509_name_list__) */
