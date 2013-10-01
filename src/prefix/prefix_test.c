/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix.h"

#include <stdio.h>
#include <string.h>

#define MUST_BE(n, expression) \
	{ if ((expression) != (n)) { printf("failed (line %d): %s must be %d\n",  __LINE__, "" #expression "", (n)); res--; } }

int prefix_to_string_test()
{
	prefix_t prefix;	
	char out[PREFIX_STRING_LENGTH];
	int res = 0;

	prefix.address = 0;
	prefix.bits = 0;
	prefix_to_string(&prefix, out);
	MUST_BE( 0, strcmp(out, "0.0.0.0/0"));

	prefix.address = 0x01020304;
	prefix.bits = 10;
	prefix_to_string(&prefix, out);
	MUST_BE( 0, strcmp(out, "1.2.3.4/10"));

	prefix.address = 0xFFFFFFFF;
	prefix.bits = 32;
	prefix_to_string(&prefix, out);
	MUST_BE( 0, strcmp(out, "255.255.255.255/32"));

	return 0;
}

int prefix_mask_test()
{
	prefix_t prefix;
	int res = 0;

	prefix.bits =  0; MUST_BE(0x00000000, prefix_mask(&prefix));
	prefix.bits =  1; MUST_BE(0x80000000, prefix_mask(&prefix));
	prefix.bits =  7; MUST_BE(0xFE000000, prefix_mask(&prefix));
	prefix.bits = 16; MUST_BE(0xFFFF0000, prefix_mask(&prefix));
	prefix.bits = 31; MUST_BE(0xFFFFFFFE, prefix_mask(&prefix));
	prefix.bits = 32; MUST_BE(0xFFFFFFFF, prefix_mask(&prefix));

	return res;
}

int prefix_contains_test()
{
	prefix_t x, y;
	int res = 0;

	x.address = 0; x.bits = 0;
	y.address = 0xFFFFFFFF; y.bits = 32;
	MUST_BE( 1, prefix_contains(&x, &y));
	MUST_BE( 0, prefix_contains(&y, &x));
	MUST_BE( 1, prefix_contains(&x, &x));
	MUST_BE( 1, prefix_contains(&y, &y));

	x.address = 0xFFFFFFFF; x.bits = 0;
	y.address = 0xFFFFFFFF; y.bits = 32;
	MUST_BE( 1, prefix_contains(&x, &y));
	MUST_BE( 0, prefix_contains(&y, &x));
	MUST_BE( 1, prefix_contains(&x, &x));
	MUST_BE( 1, prefix_contains(&y, &y));

	x.address = 0xFFFF0000; x.bits = 16;
	y.address = 0xFFFFFFFF; y.bits = 32;
	MUST_BE( 1, prefix_contains(&x, &y));
	MUST_BE( 0, prefix_contains(&y, &x));
	MUST_BE( 1, prefix_contains(&x, &x));
	MUST_BE( 1, prefix_contains(&y, &y));

	x.address = 0xFFFF0000; x.bits = 16;
	y.address = 0x0FFFFFFF; y.bits = 32;
	MUST_BE( 0, prefix_contains(&x, &y));
	MUST_BE( 0, prefix_contains(&y, &x));
	MUST_BE( 1, prefix_contains(&x, &x));
	MUST_BE( 1, prefix_contains(&y, &y));

	return res;
}

int main(void)
{
	int res = 0;
	res += prefix_to_string_test();
	res += prefix_mask_test();
	res += prefix_contains_test();

	if (res == 0) {
		printf("success\n");
	}
	return res;
}
