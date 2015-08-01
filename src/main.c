// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

#include <sodium.h>

#include "profile.h"
#include "readpassphrase.h"

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [ options ] [ output directory ]\n", program);
    fprintf(stderr, "\n");

    fprintf(stderr, "Help Options:\n");
    fprintf(stderr, "  -h, --help                Show help options\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Profile Options:\n");
    fprintf(stderr, "  -p, --profile <profile>   Specify which profile to use\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  Available Profiles:\n");
    fprintf(stderr, "      2015v1\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Output Format Options:\n");
    fprintf(stderr, "  -s, --openssh             Output OpenSSH public and private key\n");
    fprintf(stderr, "  -g, --gnupg               Output GnuPG public and private key\n");
    fprintf(stderr, "\n");
}

static struct option options[] = {
    // Output Formats.
    {"openssh", no_argument, NULL, 's'},
    {"gnupg", no_argument, NULL, 'g'},

    // Profile.
    {"profile", required_argument, NULL, 'p'},

    // Help.
    {"help", no_argument, NULL, 'h'}
};

int main(int argc, char *argv[])
{
    char option;

    // Output formats.
    bool ssh_output = false;
    bool gpg_output = false;

    // Profile options.
    char *profile_name = DEFAULT_PROFILE;

    // Output directory.
    char *output_directory = "";

    while ((option = getopt_long(argc, argv, "sghp:", options, NULL)) != -1)
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

            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        };
    }

    if (argv[optind] != NULL)
    {
        output_directory = argv[optind];
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

    printf("Generating ed25519 key using the profile '%s' ...\n", profile_name);

    return EXIT_SUCCESS;
}
