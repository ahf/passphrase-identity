// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_BASE64_H
#define GUARD_BASE64_H 1

#include <stdbool.h>

void base64_init(void);
bool base64_encode(unsigned char *input, size_t input_size, unsigned char **output, size_t *output_size);
bool base64_decode(unsigned char *input, size_t input_size, unsigned char **output, size_t *output_size);

#endif
