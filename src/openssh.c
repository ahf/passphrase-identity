// Copyright (c) 2015 Alexander Færøy. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "buffer.h"
#include "buffer_writer.h"
#include "openssh.h"

#include <sodium.h>

static bool openssh_write_public(const char *output_directory, const char *username, size_t username_length, unsigned char *public)
{
    // Public key file.
    char *public_file_path = malloc(strlen(output_directory) + 14 + 1);
    sprintf(public_file_path, "%sid_ed25519.pub", output_directory);
    int fd = 0;

    printf("Saving OpenSSH public key to %s ...\n", public_file_path);

    fd = open(public_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd == -1)
    {
        free(public_file_path);
        return false;
    }

    struct buffer *body = buffer_new(51);
    struct buffer *body_base64 = NULL;
    struct buffer_writer *body_writer = buffer_writer_new(body);

    buffer_writer_write_uint32(body_writer, 11);
    buffer_writer_write_value(body_writer, "ssh-ed25519", 11);
    buffer_writer_write_uint32(body_writer, 32);
    buffer_writer_write_value(body_writer, public, 32);

    buffer_base64_encode(body, &body_base64);

    write(fd, "ssh-ed25519 ", 12);
    write(fd, body_base64->data, body_base64->size);
    write(fd, " ", 1);
    write(fd, username, username_length);
    write(fd, "\n", 1);

    buffer_free(body);
    buffer_free(body_base64);
    buffer_writer_free(body_writer);

    close(fd);

    free(public_file_path);

    return true;
}

static bool openssh_write_secret(const char *output_directory, const char *username, size_t username_length, unsigned char *public, unsigned char *secret)
{
    char *secret_file_path = malloc(strlen(output_directory) + 10 + 1);
    sprintf(secret_file_path, "%sid_ed25519", output_directory);
    int fd = 0;

    printf("Saving OpenSSH secret key to %s ...\n", secret_file_path);

    fd = open(secret_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd == -1)
    {
        free(secret_file_path);
        return false;
    }

    uint32_t private_length = (4 + 4) + (4 + 11 + 4 + 32) + (4 + 64) + (4 + username_length);
    uint32_t padding = private_length % 8;

    if (padding != 0)
        padding = 8 - padding;

    struct buffer *body = buffer_new(15 + (4 + 4) + (4 + 4) + 4 + 4 + 4 + (4 + 11 + 4 + 32) + 4 + private_length + padding);
    struct buffer *body_base64 = NULL;
    struct buffer_writer *body_writer = buffer_writer_new(body);

    // Header.
    buffer_writer_write_value(body_writer, "openssh-key-v1\x00", 15);

    // Cipher.
    buffer_writer_write_uint32(body_writer, 4);
    buffer_writer_write_value(body_writer, "none", 4);

    // KDF.
    buffer_writer_write_uint32(body_writer, 4);
    buffer_writer_write_value(body_writer, "none", 4);

    // KDF Options.
    buffer_writer_write_uint32(body_writer, 0);

    // Number of Public Keys
    buffer_writer_write_uint32(body_writer, 1);

    // Public Keys Length.
    buffer_writer_write_uint32(body_writer, 51);

    // Public Key.
    buffer_writer_write_uint32(body_writer, 11);
    buffer_writer_write_value(body_writer, "ssh-ed25519", 11);
    buffer_writer_write_uint32(body_writer, 32);
    buffer_writer_write_value(body_writer, public, 32);

    // Private key section
    uint32_t checkint = randombytes_random();

    buffer_writer_write_uint32(body_writer, private_length + padding);

    buffer_writer_write_uint32(body_writer, checkint);
    buffer_writer_write_uint32(body_writer, checkint);

    buffer_writer_write_uint32(body_writer, 11);
    buffer_writer_write_value(body_writer, "ssh-ed25519", 11);
    buffer_writer_write_uint32(body_writer, 32);
    buffer_writer_write_value(body_writer, public, 32);

    buffer_writer_write_uint32(body_writer, 64);
    buffer_writer_write_value(body_writer, secret, 64);

    buffer_writer_write_uint32(body_writer, username_length);
    buffer_writer_write_value(body_writer, (char *)username, username_length);

    uint8_t pad = 0;
    while (padding--)
        buffer_writer_write_uint8(body_writer, ++pad & 0xff);

    // BASE64 encode the buffer.
    buffer_base64_encode(body, &body_base64);

    write(fd, "-----BEGIN OPENSSH PRIVATE KEY-----\n", 36);

    int remaining = body_base64->size;

    while (remaining >= 70)
    {
        write(fd, body_base64->data + (body_base64->size - remaining), 70);
        write(fd, "\n", 1);
        remaining -= 70;
    }

    if (remaining != 0)
    {
        write(fd, body_base64->data + (body_base64->size - remaining), remaining);
        write(fd, "\n", 1);
    }

    write(fd, "-----END OPENSSH PRIVATE KEY-----\n", 34);

    close(fd);

    buffer_free(body);
    buffer_free(body_base64);
    buffer_writer_free(body_writer);

    free(secret_file_path);

    return true;
}

bool openssh_write(const char *output_directory, const char *username, size_t username_length, unsigned char *secret, unsigned char *public)
{
    if (! openssh_write_secret(output_directory, username, username_length, public, secret))
        return false;

    if (! openssh_write_public(output_directory, username, username_length, public))
        return false;

    return true;
}
