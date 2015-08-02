// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <assert.h>

#include <sodium.h>

#include "memory.h"

void *secure_malloc(size_t size)
{
    void *result = NULL;

    result = sodium_malloc(size);
    assert(result != NULL);

    memory_zero(result, size);

    return result;
}

void secure_free(void *pointer)
{
    sodium_free(pointer);
}

void memory_zero(void *pointer, size_t size)
{
    sodium_memzero(pointer, size);
}

bool memory_equal(void *a, void *b, size_t size)
{
    return sodium_memcmp(a, b, size) == 0;
}

void memory_lock(void *pointer, size_t size)
{
    sodium_mlock(pointer, size);
}

void memory_unlock(void *pointer, size_t size)
{
    sodium_munlock(pointer, size);
}
