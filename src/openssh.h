// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_OPENSSH_H
#define GUARD_OPENSSH_H 1

#include <stdbool.h>

bool openssh_write(const char *output_directory, const char *username, size_t username_length, unsigned char *secret, unsigned char *public);

#endif
