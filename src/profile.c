// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <string.h>
#include <assert.h>

#include <sodium.h>

#include "profile.h"

#define PROFILE_2015_NAME "2015v1"
#define PROFILE_2015_USERNAME_SALT "2015v1"
#define PROFILE_2015_OPSLIMIT 33554432ULL
#define PROFILE_2015_MEMLIMIT 1073741824ULL
#define PROFILE_2015_OPENSSH_SALT ""
#define PROFILE_2015_OPENPGP_SALT "passphrase-identity-2015v1.gpg"
#define PROFILE_2015_MATERIAL_LENGTH crypto_sign_ed25519_SEEDBYTES

#define PROFILE_2017_NAME "2017"
#define PROFILE_2017_USERNAME_SALT "passphrase-identity-2017.salt"
#define PROFILE_2017_OPSLIMIT 120304050ULL
#define PROFILE_2017_MEMLIMIT 1073741824ULL
#define PROFILE_2017_OPENSSH_SALT "passphrase-identity-2017.ssh"
#define PROFILE_2017_OPENPGP_SALT "passphrase-identity-2017.gpg"
#define PROFILE_2017_MATERIAL_LENGTH 64

bool is_valid_profile_name(const char *name)
{
    if (name == NULL)
    {
        return false;
    }

    bool ok  = (0 == strcmp(name, PROFILE_2015_NAME));
         ok |= (0 == strcmp(name, PROFILE_2017_NAME));

    return ok;
}

static unsigned char * generate_material(struct profile_t * profile)
{
    assert(crypto_pwhash_scryptsalsa208sha256_SALTBYTES >= crypto_generichash_BYTES_MIN);

    bool success = false;

    unsigned char * material = sodium_malloc(profile->material_length);
    if(NULL == material)
        return NULL;

    unsigned char * salt = sodium_malloc(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    if(NULL == salt)
        goto generate_material_free_material;

    // Compute the salt from the given username and profile version.
    if(0 != crypto_generichash(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES, (const unsigned char *) profile->username, strlen(profile->username), (const unsigned char *) profile->username_salt, strlen(profile->username_salt)))
        goto generate_material_free_salt;

    if(0 == crypto_pwhash_scryptsalsa208sha256(material, profile->material_length, profile->passphrase, strlen(profile->passphrase), salt, profile->opslimit, profile->memlimit))
        success = true;

    generate_material_free_salt:
    sodium_free(salt);

    generate_material_free_material:
    if( !success )
      sodium_free(material);

    return material;
}

bool generate_openssh_keypair(struct profile_t * profile)
{
    bool success = false;

    if(NULL == profile || NULL == profile->material || profile->material_length < 16 || NULL == profile->openssh_salt)
        return false;

    unsigned char seed[crypto_sign_ed25519_SEEDBYTES];
    sodium_memzero(seed, sizeof(seed));

    // To maintain backwards compatibility with "2015v1" profile:
    if(0 == strcmp(profile->profile_name, PROFILE_2015_NAME) && crypto_sign_ed25519_SEEDBYTES == profile->material_length)
    {
        memcpy(seed, profile->material, crypto_sign_ed25519_SEEDBYTES);
    }
    else
    {
        if(0 != crypto_generichash(seed, sizeof(seed), (const unsigned char *) profile->openssh_salt, strlen(profile->openssh_salt), profile->material, profile->material_length))
            return false;
    }

    if(0 == crypto_sign_ed25519_seed_keypair((unsigned char *) &(profile->openssh_public), (unsigned char *) &(profile->openssh_secret), seed))
        success = true;

    sodium_memzero(seed, sizeof(seed));

    return success;
}

bool generate_openpgp_keypair(struct profile_t * profile)
{
    bool success = false;

    if(NULL == profile || NULL == profile->material || profile->material_length < 16 || NULL == profile->openpgp_salt)
        return false;

    if(0 == strcmp(profile->profile_name, PROFILE_2015_NAME))
    {
        // 2015 didn't have "material" originally, so we need to do a new round of scrypt for non-openssh keys
        unsigned char * salt = sodium_malloc(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
        bool salt_ok = false;
        if(NULL == salt) return false;

        if(0 != crypto_generichash(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES, (const unsigned char *) profile->username, strlen(profile->username), profile->material, profile->material_length))
            goto openpgp_free_salt;

        if(0 == crypto_pwhash_scryptsalsa208sha256(profile->openpgp_secret, sizeof(profile->openpgp_secret), profile->passphrase, strlen(profile->passphrase), salt, profile->opslimit, profile->memlimit))
            salt_ok = true;

        openpgp_free_salt:
        sodium_free(salt);

        if(!salt_ok)
            goto error;
    }
    else
    {
        if(0 != crypto_generichash(profile->openpgp_secret, sizeof(profile->openpgp_secret), (const unsigned char *) profile->openpgp_salt, strlen(profile->openpgp_salt), profile->material, profile->material_length))
            goto error;
    }

    unsigned char * secret = sodium_malloc(crypto_sign_ed25519_SECRETKEYBYTES);
    if(NULL == secret) goto error;

    if(0 == crypto_sign_ed25519_seed_keypair((unsigned char *) &(profile->openpgp_public), secret, profile->openpgp_secret))
        success = true;

    sodium_free(secret);

    error:

    return success;
}

profile_t * generate_profile(const char *profile_name, const char *username, const char *passphrase)
{

    if(NULL == profile_name || NULL == username || NULL == passphrase || 0 == strlen(profile_name))
        return NULL;

    struct profile_t * profile = sodium_malloc(sizeof(profile_t));
    if (NULL == profile)
        return NULL;

    sodium_memzero(profile, sizeof(profile_t));

    strncpy((char *) profile->username, username, sizeof(profile->username));
    strncpy((char *) profile->passphrase, passphrase, sizeof(profile->passphrase));

    if (0 == strcmp(profile_name, PROFILE_2015_NAME))
    {
        profile->profile_name    = PROFILE_2015_NAME;
        profile->username_salt   = PROFILE_2015_USERNAME_SALT;
        profile->material_length = PROFILE_2015_MATERIAL_LENGTH;
        profile->opslimit        = PROFILE_2015_OPSLIMIT;
        profile->memlimit        = PROFILE_2015_MEMLIMIT;
        profile->openssh_salt    = PROFILE_2015_OPENSSH_SALT;
        profile->openpgp_salt    = PROFILE_2015_OPENPGP_SALT;
    }

    if (0 == strcmp(profile_name, PROFILE_2017_NAME))
    {
        profile->profile_name    = PROFILE_2017_NAME;
        profile->username_salt   = PROFILE_2017_USERNAME_SALT;
        profile->material_length = PROFILE_2017_MATERIAL_LENGTH;
        profile->opslimit        = PROFILE_2017_OPSLIMIT;
        profile->memlimit        = PROFILE_2017_MEMLIMIT;
        profile->openssh_salt    = PROFILE_2017_OPENSSH_SALT;
        profile->openpgp_salt    = PROFILE_2017_OPENPGP_SALT;
    }

    profile->material = generate_material(profile);

    if (NULL == profile->material)
    {
        sodium_free(profile);
        profile = NULL;
    }

    return profile;
}

bool free_profile_t(struct profile_t * profile)
{
    bool ok = false;

    sodium_free(profile->material);

    sodium_memzero(profile, sizeof(profile_t));

    sodium_free(profile);

    return ok;
}
