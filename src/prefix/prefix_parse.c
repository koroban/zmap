/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix_parse.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Parses a string into a CIDR prefix structure.
// (See RFC4632 for CIDR notation standard.)
// Returns 0 on success, -1 on parse error.
int prefix_parse(const char *cidr, prefix_t *prefix)
{
	assert(cidr);
	assert(prefix);
	if (*cidr == '\0') {
		return -1;
	}

	uint32_t address = 0, bits = 32;
	int octet = 0, octets = 0, chars = 0;
	for (;; cidr++) {
		if (*cidr >= '0' && *cidr <= '9') {
			octet = octet * 10 + *cidr - '0';
			if (octet > 255) {
				return -1;
			}
			chars++;
			if (chars > 3) {
				return -1;
			}
		} else if (*cidr == '.' || *cidr == '/' || *cidr == '\0') {
			if (chars == 0) {
				return -1;
			}
			address = (address << 8) | octet;
			octets++;
			if (octets > 4) {
				return -1;
			}
			octet = 0;
			chars = 0;
			if (*cidr == '/' || *cidr == '\0') {
				break;
			}
		} else {
			return -1;
		}
	}
	if (*cidr == '/') {
		bits = 0;
		cidr++;
		for (; *cidr >= '0' && *cidr <= '9'; cidr++) {
			bits = bits * 10 + *cidr - '0';
			if (bits > 32) {
				return -1;
			}
			chars++;
			if (chars > 2) {
				return -1;
			}
		}
		if (chars == 0) {
			return -1;
		}
		if (bits > octets*8) {
			return -1;
		}
		for ( ; octets < 4; octets++) {
			address <<= 8;
		}
	}
	if (*cidr != '\0') {
		return -1;
	}
	if (octets < 4) {
		return -1;
	}

	prefix->bits = bits;
	prefix->address = address & prefix_mask(prefix);
	return 0;
}

// Parses a line (e.g., form an input file) possibly
// containing a CIDR notated prefix.  Allows whitespace
// before and after the prefix and comments (to end of line)
// beginning with a # character.
// Returns:
//    0 if *prefix contains a parsed prefix
//    1 if line was empty or only comments
//   -1 on parse error
int prefix_parse_line(const char *input, prefix_t *prefix)
{
	assert(input);
	assert(prefix);
	char *line = strdup(input);
	assert(line);

	// remove leading whitespace
	char *start = line;
	for ( ; *start != '\0'; start++) {
		if (*start != ' ' && *start != '\t') {
			break;
		}
	}

	// remove trailing whitespace or comments
	char *end = start;
	for (char *c = start; *c != '\0' && *c != '#'; c++) {
		if (*c != ' ' && *c != '\t') {
			end = c+1;
		}
	}
	*end = '\0';

	int ret;
	if (start == end) {
		ret = 1;
	} else {
		ret = prefix_parse(start, prefix);
	}

	free(line);
	return ret;
}
