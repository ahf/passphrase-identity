// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <string.h>

#include "profile.h"

bool is_valid_profile_name(const char *name)
{
    if (name == NULL)
    {
        return false;
    }

    return strcmp(name, "2015v1") == 0;
}
