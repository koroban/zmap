/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix.h"

#include <stdio.h>
#include <assert.h>

// Generates a string from a CIDR prefix structure.
void prefix_to_string(const prefix_t *prefix, char output[PREFIX_STRING_LENGTH])
{
	assert(prefix);
	assert(output);
	snprintf(output, PREFIX_STRING_LENGTH, "%01d.%01d.%01d.%01d/%01d",
			 (prefix->address >> 24) & 0xFF, (prefix->address >> 16) & 0xFF,
			 (prefix->address >>  8) & 0xFF, (prefix->address      ) & 0xFF,
			 prefix->bits);
}

// Returns a bitmask for the significant bits of prefix.
uint32_t prefix_mask(const prefix_t *prefix)
{
	assert(prefix);
	assert(prefix->bits >= 0 && prefix->bits <= 32);
	if (prefix->bits == 0) {
		return 0;
	}
	return (0xFFFFFFFF << (32-prefix->bits));
}

// Returns 1 if prefix outer contains prefix inner or if they are equal.
int prefix_contains(const prefix_t *outer, const prefix_t *inner)
{
	assert(outer);
	assert(inner);
	return (inner->bits >= outer->bits) &&
		((inner->address & prefix_mask(outer)) == (outer->address & prefix_mask(outer)));
}
