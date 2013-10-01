/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix_constraint.h"

#include <stdio.h>
#include <assert.h>

int constraint_test()
{
	constraint_t *con;
	int res = 0;

	con = constraint_init();
	assert(con);
	constraint_destroy(con);
}

int main(void)
{
	int res = 0;
	res += constraint_test();

	if (res == 0) {
		printf("success\n");
	}
	return res;
}
	
