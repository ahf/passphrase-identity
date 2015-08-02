// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_MEMORY_H
#define GUARD_MEMORY_H 1

#include <stdbool.h>
#include <stdlib.h>

void *secure_malloc(size_t size);
void secure_free(void *pointer);

void memory_zero(void *pointer, size_t size);
bool memory_equal(void *a, void *b, size_t size);

void memory_lock(void *pointer, size_t size);
void memory_unlock(void *pointer, size_t size);

#endif
