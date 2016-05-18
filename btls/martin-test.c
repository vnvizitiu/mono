//
//  martin-test.c
//  MonoBtls
//
//  Created by Martin Baulig on 5/17/16.
//  Copyright © 2016 Xamarin. All rights reserved.
//

#include <martin-test.h>

extern void mono_btls_martin_test (void);

int
main (int argc, char **argv)
{
	mono_btls_martin_test ();
	return 0;
}
