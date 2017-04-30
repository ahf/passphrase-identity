// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <getopt.h>

#include <sodium.h>

#include "buffer.h"
#include "openssh.h"
#include "openpgp.h"
#include "profile.h"
#include "readpassphrase.h"
#include "memory.h"

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [ options ] [ output directory ]\n", program);
    fprintf(stderr, "\n");

    fprintf(stderr, "Help Options:\n");
    fprintf(stderr, "  -h, --help                Show help options\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Key Options:\n");
    fprintf(stderr, "  -u, --user <username>     Specify which username to use\n");
    fprintf(stderr, "  -p, --profile <profile>   Specify which profile to use\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Available Profiles:\n");
    fprintf(stderr, "      2015v1\n");
    fprintf(stderr, "      2017\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Output Format Options:\n");
    fprintf(stderr, "  -s, --openssh             Output OpenSSH public and private key\n");
    fprintf(stderr, "  -g, --gpg                 Output OpenPGP public and private key\n");
    fprintf(stderr, "\n");
}

static struct option options[] = {
    // Output Formats.
    {"openssh", no_argument, NULL, 's'},
    {"gpg", no_argument, NULL, 'g'},

    // Key Options.
    {"profile", required_argument, NULL, 'p'},
    {"user", required_argument, NULL, 'u'},

    // Help.
    {"help", no_argument, NULL, 'h'},

    // End of option array:
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    char option;
    bool success = true;

    // Output formats.
    bool ssh_output = false;
    bool gpg_output = false;

    // Key options.
    char *profile_name = DEFAULT_PROFILE;

    char *username = NULL;
    size_t username_length = 0;

    // Output directory.
    char *output_directory = NULL;

    // Passphrase.
    char passphrase[1024];
    char passphrase_verify[sizeof passphrase];

    // Initialize base64 encoder and decoder.
    buffer_init();

    while ((option = getopt_long(argc, argv, "gshu:p:", options, NULL)) != -1)
    {
        switch (option)
        {
            case 's':
                ssh_output = true;
                break;

            case 'g':
                gpg_output = true;
                break;

            case 'p':
                profile_name = optarg;
                break;

            case 'u':
                username = optarg;
                username_length = strlen(username);
                sodium_mlock(username, username_length);
                break;

            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        };
    }

    if (argv[optind] != NULL)
    {
        output_directory = argv[optind];
    }

    // Username is required.
    if (username == NULL)
    {
        fprintf(stderr, "Error: Missing username option ...\n");
        return EXIT_FAILURE;
    }

    // We want at least one output format.
    if (! (ssh_output || gpg_output))
    {
        fprintf(stderr, "Error: Missing output format(s) ...\n");
        return EXIT_FAILURE;
    }

    if (! is_valid_profile_name(profile_name))
    {
        fprintf(stderr, "Error: Invalid profile '%s' ...\n", profile_name);
        return EXIT_FAILURE;
    }

    if (sodium_init() == -1)
    {
        fprintf(stderr, "Error: Unable to initialize libsodium ...\n");
        return EXIT_FAILURE;
    }

    sodium_mlock(passphrase, sizeof(passphrase));
    sodium_mlock(passphrase_verify, sizeof(passphrase_verify));
    memory_zero(passphrase, sizeof passphrase);
    memory_zero(passphrase_verify, sizeof passphrase);

    if(NULL == readpassphrase("Enter passphrase: ", passphrase, sizeof(passphrase), RPP_ECHO_OFF)
    || NULL == readpassphrase("Confirm passphrase: ", passphrase_verify, sizeof(passphrase), RPP_ECHO_OFF))
    {
        fprintf(stderr, "Error: Program failed to read passphrases.\n");
        success = false;
        goto cleanup_passphrase_and_exit;
    }

    if(0 != strncmp(passphrase, passphrase_verify, sizeof(passphrase_verify)))
    {
        fprintf(stderr, "Error: Passphrases do not match.\n");
        success = false;
        goto cleanup_passphrase_and_exit;
    }

    if(strlen(passphrase) < 12)
    {
        fprintf(stderr, "Error: Provided passphrase is shorter than 12 characters.\n");
        success = false;
        goto cleanup_passphrase_and_exit;
    }

    printf("Generating key material using the '%s' profile ...\n", profile_name);
    printf("This may take a little while ...\n");

    struct profile_t * profile = generate_profile(profile_name, username, passphrase);

    if (ssh_output)
    {
        if (generate_openssh_keypair(profile))
        {
            printf("Successfully generated SSH key pair ...\n");
            // TODO check return val of this or make it a void(*)(..)
            openssh_write(output_directory, profile->username, strlen(profile->username), (unsigned char *) &(profile->openssh_secret), (unsigned char *) &(profile->openssh_public));
        }
        else
        {
            fprintf(stderr, "Error: Unable to generate SSH key pair ...\n");
            success = false;
        }
    }

    if (gpg_output)
    {
        if (generate_openpgp_keypair(profile))
        {
            printf("Successfully generated OpenPGP key pair ...\n");
            if (openpgp_write(output_directory, profile))
            {
                printf("Successfully wrote OpenPGP key pair to disk.\n");
            }
            else
            {
                fprintf(stderr, "Failed to write OpenPGP key pair to disk...\n");
                success = false;
            }
        }
        else
        {
            fprintf(stderr, "Error: Unable to generate GPG key pair ...\n");
            success = false;
        }
    }

    free_profile_t(profile);
    sodium_munlock(username, username_length);

cleanup_passphrase_and_exit:
    sodium_munlock(passphrase, sizeof(passphrase));
    sodium_munlock(passphrase_verify, sizeof(passphrase_verify));

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
