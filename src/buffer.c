// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <string.h>

#include <sodium.h>

#include "buffer.h"
#include "memory.h"

static unsigned char base64_encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static unsigned char base64_decoding_table[256];

static int base64_mod_table[] = { 0, 2, 1 };

void __attribute__((constructor)) buffer_init(void)
{
    for (int i = 0; i < 64; ++i)
    {
        base64_decoding_table[base64_encoding_table[i]] = i;
    }
}

struct buffer* MUSTCHECK buffer_new(size_t size)
{
    struct buffer *buffer = NULL;

    buffer = malloc(sizeof(*buffer));
    if (NULL == buffer)
        return NULL;

    buffer->size = size;
    // We allocate an extra byte, which is always set to zero.
    buffer->data = secure_malloc(size + 1);

    if (NULL == buffer->data)
    {
        memory_zero(buffer, sizeof(buffer));
        free(buffer);
        buffer = NULL;
    }

    return buffer;
}

struct buffer* MUSTCHECK buffer_new_from_string(char *string)
{
    if (string == NULL)
        return NULL;

    return buffer_new_from_raw_buffer((unsigned char *)string, strlen(string));
}

struct buffer* MUSTCHECK buffer_new_random(size_t size)
{
    struct buffer *buffer = NULL;

    buffer = buffer_new(size);
    if (NULL != buffer)
        randombytes_buf(buffer->data, size);

    return buffer;
}

struct buffer* MUSTCHECK buffer_new_from_raw_buffer(unsigned char *data, size_t size)
{
    struct buffer *buffer = NULL;

    if(NULL == data)
        return NULL;

    buffer = buffer_new(size);
    if (NULL != buffer)
        memcpy(buffer->data, data, size);

    return buffer;
}

void buffer_free(struct buffer *buffer)
{
    if (buffer == NULL)
        return;

    if (buffer->data != NULL)
    {
        // shred the data:
        secure_free(buffer->data);
        buffer->data = NULL;
    }

    // get rid of ->data pointer + ->size:
    sodium_memzero(buffer, sizeof(struct buffer));
    free(buffer);
}

char *buffer_string(const struct buffer *buffer)
{
    if (buffer == NULL)
        return NULL;

    return (char *)buffer->data;
}

size_t buffer_size(const struct buffer *buffer)
{
    if (buffer == NULL)
        return 0;

    return buffer->size;
}

bool MUSTCHECK buffer_equal(const struct buffer *buffer, const struct buffer *other_buffer)
{
    if (buffer == NULL || other_buffer == NULL)
        return false;

    if (buffer->size != other_buffer->size)
        return false;

    if (NULL == buffer->data || NULL == other_buffer->data)
        return false;

    return memory_equal(buffer->data, other_buffer->data, buffer->size);
}

bool MUSTCHECK buffer_hex_encode(const struct buffer *buffer, struct buffer **result)
{
    struct buffer *value = NULL;

    if (buffer == NULL || result == NULL)
        return false;

    value = buffer_new(buffer->size * 2);
    if (NULL == value)
        return false;

    sodium_bin2hex((char *)value->data, value->size, buffer->data, buffer->size);

    *result = value;

    return true;
}

bool MUSTCHECK buffer_hex_decode(const struct buffer *buffer, struct buffer **result)
{
    struct buffer *value = NULL;

    if (buffer == NULL || result == NULL)
        return false;

    value = buffer_new(buffer->size / 2);
    if (NULL == value)
        return false;

    sodium_hex2bin(value->data, value->size, (char *)buffer->data, buffer->size, ": ", NULL, NULL);
    *result = value;

    return true;
}

bool MUSTCHECK buffer_base64_encoded_size(const struct buffer *buffer, size_t *projected_size)
{
    if(NULL == buffer || NULL == projected_size)
        return false;

    // check for overflow, rounding down:
    if(buffer->size > ((SIZE_MAX-3) / 4) * 3)
        return false;

    // see implementation in buffer_base64_encode below
    *projected_size = 4 * ((buffer->size + 2)/3);
    return true;
}

bool MUSTCHECK buffer_base64_encode(const struct buffer *buffer, struct buffer **result)
{
    struct buffer *value = NULL;

    if (buffer == NULL || result == NULL)
        return false;

    size_t encoded_size = 0;
    if(!buffer_base64_encoded_size(buffer, &encoded_size))
        return false;

    value = buffer_new(encoded_size);
    if (NULL == value)
        return false;

    for (size_t i = 0, j = 0; i < buffer->size; )
    {
        uint32_t a = i < buffer->size ? buffer->data[i++] : 0;
        uint32_t b = i < buffer->size ? buffer->data[i++] : 0;
        uint32_t c = i < buffer->size ? buffer->data[i++] : 0;
        uint32_t triplet = (a << 0x10) + (b << 0x08) + c;

        value->data[j++] = base64_encoding_table[(triplet >> 3 * 6) & 0x3F];
        value->data[j++] = base64_encoding_table[(triplet >> 2 * 6) & 0x3F];
        value->data[j++] = base64_encoding_table[(triplet >> 1 * 6) & 0x3F];
        value->data[j++] = base64_encoding_table[(triplet >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < base64_mod_table[buffer->size % 3]; i++)
        value->data[value->size - 1 - i] = '=';

    *result = value;

    return true;
}

bool MUSTCHECK buffer_base64_decoded_size(const struct buffer *buffer, size_t *projected_size)
{
    if(NULL == buffer || NULL == projected_size)
        return false;

    if (buffer->size % 4 != 0) return false;
//    {
//        if(buffer->size % 4 == 1 && '\0' != *(buffer->data + buffer->size -1))
//          return false;
//    }

    *projected_size = (buffer->size / 4) * 3;

    return true;
}

bool MUSTCHECK buffer_base64_decode(const struct buffer *buffer, struct buffer **result)
{
    struct buffer *value = NULL;
    size_t value_size = 0;

    if (NULL == result)
        return false;

    // make sure decoding table is initiated:
    if('3' != base64_decoding_table[base64_encoding_table['3']])
        buffer_init();

    if(!buffer_base64_decoded_size(buffer, &value_size))
        return false;

    if (buffer->data[buffer->size - 1] == '=')
        --value_size;

    if (buffer->data[buffer->size - 2] == '=')
        --value_size;

    value = buffer_new(value_size);
    if (NULL == value)
        return false;

    for (size_t i = 0, j = 0; i < buffer->size; )
    {
        uint32_t a = buffer->data[i] == '=' ? 0 & i++ : base64_decoding_table[buffer->data[i++]];
        uint32_t b = buffer->data[i] == '=' ? 0 & i++ : base64_decoding_table[buffer->data[i++]];
        uint32_t c = buffer->data[i] == '=' ? 0 & i++ : base64_decoding_table[buffer->data[i++]];
        uint32_t d = buffer->data[i] == '=' ? 0 & i++ : base64_decoding_table[buffer->data[i++]];

        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < value->size)
            value->data[j++] = (triple >> 2 * 8) & 0xFF;

        if (j < value->size)
            value->data[j++] = (triple >> 1 * 8) & 0xFF;

        if (j < value->size)
            value->data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    *result = value;

    return true;
}
