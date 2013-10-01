/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PREFIX_H
#define PREFIX_H

#include <stdint.h>

typedef struct prefix_struct {
	uint32_t address;
	uint8_t bits;
} prefix_t;

#define PREFIX_STRING_LENGTH 19
void prefix_to_string(const prefix_t *prefix, char output[PREFIX_STRING_LENGTH]);

uint32_t prefix_mask(const prefix_t *prefix);
int prefix_contains(const prefix_t *outer, const prefix_t *inner);

#endif //PREFIX_H
