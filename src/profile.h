// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef GUARD_PROFILE_H
#define GUARD_PROFILE_H 1

#include <stdbool.h>
#include <stdlib.h>
#include <sodium.h>

#define DEFAULT_PROFILE "2017"

typedef struct profile_t
{
    // Inline the integers to avoid having to deal with pointer lifetime:
    size_t material_length;
    unsigned long long opslimit;
    unsigned long long memlimit;

    // These are always set to global pointers to PROFILE_20##_* constants:
    char * profile_name;
    char * username_salt;
    char * openssh_salt;
    char * openpgp_salt;

    unsigned char * material;

    // Inline these to keep them in the sodium_malloc() buffer:
    char passphrase[256];
    char username[90];

    char openssh_secret[crypto_sign_ed25519_SECRETKEYBYTES];
    // Note that PGP stores the seed ("d") and computes the actual private key
    // for every signature. Internally it just stores "d".
    unsigned char openpgp_secret[crypto_sign_ed25519_SEEDBYTES];

    char openssh_public[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char openpgp_public[crypto_sign_ed25519_PUBLICKEYBYTES];
} profile_t;

bool is_valid_profile_name(const char *profile_name);

struct profile_t * generate_profile(const char *profile_name, const char *username, const char *passphrase);

bool generate_openssh_keypair(struct profile_t * profile);
bool generate_openpgp_keypair(struct profile_t * profile);

bool free_profile_t(struct profile_t * profile);

#endif
