/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef PREFIX_CONSTRAINT_H
#define PREFIX_CONSTRAINT_H

#include "prefix.h"

typedef struct constraint_struct constraint_t;

constraint_t *constraint_init(void);
void constraint_destroy(constraint_t *con);
void constraint_allow(constraint_t *con, const prefix_t *prefix);
void constraint_deny(constraint_t *con, const prefix_t *prefix);


#endif //PREFIX_CONSTRAINT_H
