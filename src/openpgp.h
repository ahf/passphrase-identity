// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_OPENPGP_H
#define GUARD_OPENPGP_H 1

#include "profile.h"
#include <stdbool.h>

bool openpgp_write(const char *output_directory, const struct profile_t *profile);

#endif
