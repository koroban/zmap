/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "prefix_constraint.h"

#include <stdlib.h>
#include <assert.h>

typedef struct constraint_struct {
	int inited;
	node_t *root;
} constraint_t;

typedef uint8_t value_t;
const value_t VALUE_ALLOWED = 1;
const value_t VALUE_DISALLOWED = 0;

typedef struct node_struct {
	struct node_struct *l;
	struct node_struct *r;
	value_t value;	
} node_t;

#define IS_LEAF(node) ((node)->l == NULL)

static node_t* _create_leaf(value_t value)
{
	node_t *node = malloc(sizeof(node_t));
	assert(node);
	node->l = NULL;
	node->r = NULL;
	node->value = value;
	return node;
}

static void _destroy_subtree(node_t *root)
{
	if (node == NULL)
		return;
	_destroy_subtree(node->l);
	_destroy_subtree(node->r);
	free(node);
}

static void _convert_to_leaf(node_t *node, value_t value)
{
	assert(node);
	if (!IS_LEAF(node)) {
		_destroy_subtree(node->l);
		_destroy_subtree(node->r);	
		node->l = NULL;
		node->r = NULL;
	}
	node->value = value;
}

static void _convert_to_internal(node_t *node)
{
	assert(node);
	assert(IS_LEAF(node));
	node->l = _create_leaf(node->value);
	node->r = _create_leaf(node->value);
}

static void _set_constraint(node_t node, uint32_t prefix, int bits, value_t value)
{
	assert(node);
	assert(0 <= bits && bits <= 32);

	if (bits == 0) {
		// We're at the end of the prefix; make sure this is a leaf and set the value.
		_convert_to_leaf(node, value);
		return;
	}
	
	if (IS_LEAF(node)) {
		// We're not at the end of the prefix, but we hit a leaf.
		if (node->value == value) {
			// A larger prefix has the same value, so we're done.
			return;
		}
		// The larger prefix has a different value, so we need to convert it
		// into an internal node and continue processing on one of the leaves.
		_convert_to_internal(node);
	}

	// We're not at the end of the prefix, and we're at an internal
	// node.  Recurse on the left or right subtree.
	if (prefix & 0x80000000) {
		_set_constraint(node->r, prefix << 1, bits-1, value);
	} else {
		_set_constraint(node->l, prefix << 1, bits-1, value);
	}	

	// At this point, we're an internal node, and the value is set
	// by one of our children or its descendent.  If both children are
	// leaves with the same value, we can discard them and become a leaf.
	if (IS_LEAF(node->r) && IS_LEAF(node->l) && (node->r->value == node->l->value)) {
		_convert_to_leaf(node, node->l->value);
	}
}

constraint_t *constraint_init(void)
{
	constraint_t *con = malloc(sizeof(constraint_t));
	assert(con);
	con->inited = 1;
	con->root = _create_leaf(VALUE_DISALLOWED);
	return con;
}

void constraint_destroy(constraint_t *con)
{
	assert(con);
	assert(con->inited);
	con->inited = 0;
	_destroy_subtree(con->root);
	free(con);
}

void constraint_allow(constraint_t *con, const prefix_t *prefix)
{
	assert(con);
	assert(prefix);
	_constraint_set(con->root, prefix->bits, prefix->bits, VALUE_ALLOWED);
}

void constraint_deny(constraint_t *con, const prefix_t *prefix)
{
	assert(con);
	assert(prefix);
	_constraint_set(con->root, prefix->bits, prefix->bits, VALUE_DISALLOWED);
}
