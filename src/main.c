// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [ options ] <output directory>\n", program);
    fprintf(stderr, "\n");

    fprintf(stderr, "Help Options\n");
    fprintf(stderr, "  -h, --help          Show help options\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Output Format Options\n");
    fprintf(stderr, "  -s, --ssh           Output OpenSSH public and private key\n");
    fprintf(stderr, "  -g, --gpg           Output GnuPG public and private key\n");
    fprintf(stderr, "\n");
}

static struct option options[] = {
    // Output Formats.
    {"ssh", no_argument, NULL, 's'},
    {"gpg", no_argument, NULL, 'g'},

    // Help.
    {"help", no_argument, NULL, 'h'}
};

int main(int argc, char *argv[])
{
    char option;

    // Output formats.
    bool ssh_output = false;
    bool gpg_output = false;

    // Output directory.
    char *output_directory = NULL;

    while ((option = getopt_long(argc, argv, "sgh", options, NULL)) != -1)
    {
        switch (option)
        {
            case 's':
                ssh_output = true;
                break;

            case 'g':
                gpg_output = true;
                break;

            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        };
    }

    output_directory = argv[optind];

    // We want at least one output format.
    if (! (ssh_output || gpg_output))
    {
        fprintf(stderr, "Error: Missing output format(s) ...\n");
        return EXIT_FAILURE;
    }

    if (output_directory == NULL)
    {
        fprintf(stderr, "Error: Missing output directory ...\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
