/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PREFIX_PARSE_H
#define PREFIX_PARSE_H

#include "prefix.h"

int prefix_parse(const char *cidr, prefix_t *prefix);
int prefix_parse_line(const char *input, prefix_t *prefix);

#endif //PREFIX_PARSE_H
