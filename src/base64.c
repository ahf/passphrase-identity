// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <stdbool.h>

#include <sodium.h>

#include "base64.h"

static char base64_encoding_table[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static char base64_decoding_table[256];

static int base64_mod_table[] = { 0, 2, 1 };

void base64_init(void)
{
    for (int i = 0; i < 64; ++i)
    {
        base64_decoding_table[(unsigned char)base64_encoding_table[i]] = i;
    }
}

bool base64_encode(unsigned char *input, size_t input_size, unsigned char **output, size_t *output_size)
{
    unsigned char *value = NULL;

    if (input == NULL || output == NULL || output_size == NULL)
        return false;

    *output_size = 4 * ((input_size + 2) / 3);

    value = sodium_malloc(*output_size);

    for (size_t i = 0, j = 0; i < input_size; )
    {
        uint32_t a = i < input_size ? input[i++] : 0;
        uint32_t b = i < input_size ? input[i++] : 0;
        uint32_t c = i < input_size ? input[i++] : 0;
        uint32_t triplet = (a << 0x10) + (b << 0x08) + c;

        value[j++] = base64_encoding_table[(triplet >> 3 * 6) & 0x3F];
        value[j++] = base64_encoding_table[(triplet >> 2 * 6) & 0x3F];
        value[j++] = base64_encoding_table[(triplet >> 1 * 6) & 0x3F];
        value[j++] = base64_encoding_table[(triplet >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < base64_mod_table[input_size % 3]; i++)
        value[*output_size - 1 - i] = '=';

    *output = value;

    return true;
}

bool base64_decode(unsigned char *input, size_t input_size, unsigned char **output, size_t *output_size)
{
    unsigned char *value = NULL;
    size_t value_size = 0;

    if (input == NULL || output == NULL || output_size == NULL)
        return false;

    if (input_size % 4 != 0)
        return false;

    value_size = input_size / 4 * 3;

    if (input[input_size - 1] == '=')
        --value_size;

    if (input[input_size - 2] == '=')
        --value_size;

    value = sodium_malloc(value_size);

    for (size_t i = 0, j = 0; i < input_size; )
    {
        uint32_t a = input[i] == '=' ? 0 & i++ : base64_decoding_table[input[i++]];
        uint32_t b = input[i] == '=' ? 0 & i++ : base64_decoding_table[input[i++]];
        uint32_t c = input[i] == '=' ? 0 & i++ : base64_decoding_table[input[i++]];
        uint32_t d = input[i] == '=' ? 0 & i++ : base64_decoding_table[input[i++]];

        uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (j < value_size)
            value[j++] = (triple >> 2 * 8) & 0xFF;

        if (j < value_size)
            value[j++] = (triple >> 1 * 8) & 0xFF;

        if (j < value_size)
            value[j++] = (triple >> 0 * 8) & 0xFF;
    }

    *output = value;
    *output_size = value_size;

    return true;
}
