/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix_parse.h"

#include <stdio.h>
#include <string.h>

#define MUST_BE(n, expression) \
	{ if ((expression) != (n)) { printf("failed (line %d): %s must be %d\n",  __LINE__, "" #expression "", (n)); res--; } }

int prefix_parse_test()
{
	prefix_t prefix;
	int res = 0;

	MUST_BE( 0, prefix_parse("0/0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE( 0, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0/0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE( 0, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0.0/0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE( 0, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0.0.0/0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE( 0, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0.0.0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("255.255.255.255", &prefix));
	MUST_BE(0xFFFFFFFF, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("255.255.255.255/32", &prefix));
	MUST_BE(0xFFFFFFFF, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0.0.255", &prefix));
	MUST_BE(0x000000FF, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("0.0.255.0", &prefix));
	MUST_BE(0x0000FF00, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("0.255.0.0", &prefix));
	MUST_BE(0x00FF0000, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("255.0.0.0", &prefix));
	MUST_BE(0xFF000000, prefix.address);
	MUST_BE(32, prefix.bits);
	MUST_BE( 0, prefix_parse("255/8", &prefix));
	MUST_BE(0xFF000000, prefix.address);
	MUST_BE(8, prefix.bits);
	MUST_BE( 0, prefix_parse("255.255/16", &prefix));
	MUST_BE(0xFFFF0000, prefix.address);
	MUST_BE(16, prefix.bits);
	MUST_BE( 0, prefix_parse("255.255/8", &prefix));
	MUST_BE(0xFF000000, prefix.address);
	MUST_BE(8, prefix.bits);

	MUST_BE(-1, prefix_parse("", &prefix));
	MUST_BE(-1, prefix_parse("0.0.0.0.0", &prefix));
	MUST_BE(-1, prefix_parse(" 0.0.0.0", &prefix));
	MUST_BE(-1, prefix_parse("0.0.0.0 ", &prefix));
	MUST_BE(-1, prefix_parse("0.0. 0.0", &prefix));
	MUST_BE(-1, prefix_parse("0.0.0 0.0", &prefix));
	MUST_BE(-1, prefix_parse("0.0.0 .0", &prefix));
	MUST_BE(-1, prefix_parse("0", &prefix));
	MUST_BE(-1, prefix_parse("0.", &prefix));
	MUST_BE(-1, prefix_parse("0./", &prefix));
	MUST_BE(-1, prefix_parse(".0", &prefix));
	MUST_BE(-1, prefix_parse(".", &prefix));
	MUST_BE(-1, prefix_parse("..", &prefix));
	MUST_BE(-1, prefix_parse("/", &prefix));
	MUST_BE(-1, prefix_parse("0.0", &prefix));
	MUST_BE(-1, prefix_parse("0/", &prefix));
	MUST_BE(-1, prefix_parse("0/ ", &prefix));
	MUST_BE(-1, prefix_parse("0/ 0", &prefix));
	MUST_BE(-1, prefix_parse("0/0 0", &prefix));
	MUST_BE(-1, prefix_parse("0/.", &prefix));
	MUST_BE(-1, prefix_parse("0./", &prefix));
	MUST_BE(-1, prefix_parse("/0", &prefix));
	MUST_BE(-1, prefix_parse("./", &prefix));
	MUST_BE(-1, prefix_parse("256/0", &prefix));
	MUST_BE(-1, prefix_parse("0000/0", &prefix));
	MUST_BE(-1, prefix_parse("1000/0", &prefix));
	MUST_BE(-1, prefix_parse("0/33", &prefix));
	MUST_BE(-1, prefix_parse("0/000", &prefix));
	MUST_BE(-1, prefix_parse("0/001", &prefix));
	MUST_BE(-1, prefix_parse("0.0.0.256", &prefix));
	MUST_BE(-1, prefix_parse("0/9", &prefix));

	return res;
}

int prefix_parse_line_test()
{
	prefix_t prefix;
	int res = 0;

	MUST_BE( 0, prefix_parse_line("0/0", &prefix));
	MUST_BE( 0, prefix.address);
	MUST_BE( 0, prefix.bits);
	MUST_BE( 0, prefix_parse("255.255/8", &prefix));
	MUST_BE( 0xFF000000, prefix.address);
	MUST_BE( 8, prefix.bits);
	MUST_BE( 0, prefix_parse_line("1.2.3.4/24", &prefix));
	MUST_BE( 0x01020300, prefix.address);
	MUST_BE( 24, prefix.bits);
	MUST_BE( 0, prefix_parse_line("1.2.3.4/24 # comment", &prefix));
	MUST_BE( 0x01020300, prefix.address);
	MUST_BE( 24, prefix.bits);
	MUST_BE( 0, prefix_parse_line("\t1.2.3.4/24\t# comment", &prefix));
	MUST_BE( 0x01020300, prefix.address);
	MUST_BE( 24, prefix.bits);
	MUST_BE( 0, prefix_parse_line("  1.2.3.4/24  # comment", &prefix));
	MUST_BE( 0x01020300, prefix.address);
	MUST_BE( 24, prefix.bits);
	MUST_BE( 1, prefix_parse_line("", &prefix));
	MUST_BE( 1, prefix_parse_line(" ", &prefix));
	MUST_BE( 1, prefix_parse_line("   ", &prefix));
	MUST_BE( 1, prefix_parse_line("\t", &prefix));
	MUST_BE( 1, prefix_parse_line(" \t", &prefix));
	MUST_BE( 1, prefix_parse_line(" \t ", &prefix));
	MUST_BE( 1, prefix_parse_line("#", &prefix));
	MUST_BE( 1, prefix_parse_line("# 0", &prefix));
	MUST_BE( 1, prefix_parse_line("# 0.0.0.0/0", &prefix));
	MUST_BE( 1, prefix_parse_line("# xxx", &prefix));
	MUST_BE( 1, prefix_parse_line(" #", &prefix));
	MUST_BE( 1, prefix_parse_line("\t#", &prefix));
	MUST_BE(-1, prefix_parse_line("0", &prefix));
	MUST_BE(-1, prefix_parse_line(" 0", &prefix));
	MUST_BE(-1, prefix_parse_line("0 ", &prefix));
	MUST_BE(-1, prefix_parse_line(" 0 ", &prefix));
	MUST_BE(-1, prefix_parse_line("a", &prefix));
	MUST_BE(-1, prefix_parse_line("a", &prefix));
	MUST_BE(-1, prefix_parse_line("0.0.0.0 abc", &prefix));

	return res;
}

int main(void)
{
	int res = 0;
	res += prefix_parse_test();
	res += prefix_parse_line_test();
	
	if (res == 0) {
		printf("success\n");
	}
	return res;
}
