// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <string.h>
#include <assert.h>

#include <sodium.h>

#include "profile.h"

#define PROFILE_2015V1_OPSLIMIT 33554432ULL
#define PROFILE_2015V1_MEMLIMIT 1073741824ULL

bool is_valid_profile_name(const char *name)
{
    if (name == NULL)
    {
        return false;
    }

    return strcmp(name, "2015v1") == 0;
}

static bool generate_2015v1_keypair(const char *username, size_t username_length, const char *passphrase, size_t passphrase_length, unsigned char *secret, unsigned char *public)
{
    assert(crypto_pwhash_scryptsalsa208sha256_SALTBYTES == crypto_generichash_BYTES);

    bool success = true;

    // Seed for the ed25519 keys.
    unsigned char seed[crypto_sign_SEEDBYTES];
    sodium_mlock(seed, sizeof(seed));

    // Compute the salt from the given username and profile version.
    unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    crypto_generichash(salt, sizeof(salt), (const unsigned char *)username, username_length, (const unsigned char *)"2015v1", 6);

    if (crypto_pwhash_scryptsalsa208sha256(seed, sizeof(seed), passphrase, passphrase_length, salt, PROFILE_2015V1_OPSLIMIT, PROFILE_2015V1_MEMLIMIT) != 0)
    {
        success = false;
    }
    else
    {
        crypto_sign_seed_keypair(public, secret, seed);
    }

    sodium_munlock(seed, sizeof(seed));

    return success;
}

bool generate_keypair(const char *profile, const char *username, size_t username_length, const char *passphrase, size_t passphrase_length, unsigned char *secret, unsigned char *public)
{
    assert(profile != NULL);
    assert(username != NULL);
    assert(passphrase != NULL);
    assert(secret != NULL);
    assert(public != NULL);

    if (strcmp(profile, "2015v1") == 0)
    {
        return generate_2015v1_keypair(username, username_length, passphrase, passphrase_length, secret, public);
    }

    return false;
}
