// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_BUFFER_H
#define GUARD_BUFFER_H 1

#include <stdbool.h>
#include <sys/types.h>

struct buffer
{
    size_t size;
    unsigned char *data;
};

void buffer_init(void);

struct buffer* buffer_new(size_t size);
struct buffer* buffer_new_from_string(char *string);
struct buffer* buffer_new_from_raw_buffer(unsigned char *data, size_t size);
struct buffer* buffer_new_random(size_t size);

void buffer_free(struct buffer *buffer);

const char *buffer_string(struct buffer *buffer);
size_t buffer_size(struct buffer *buffer);

bool buffer_equal(struct buffer *buffer, struct buffer *other_buffer);

bool buffer_hex_encode(struct buffer *buffer, struct buffer **result);
bool buffer_hex_decode(struct buffer *buffer, struct buffer **result);

bool buffer_base64_encode(struct buffer *buffer, struct buffer **result);
bool buffer_base64_decode(struct buffer *buffer, struct buffer **result);

#endif
