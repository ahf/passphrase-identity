#include <assert.h>

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "openpgp.h"
#include "profile.h"
#include "buffer.h"
#include "buffer_writer.h"
#include "sha.h"

// our OpenPGP constants
#define PGP_single_octet_length 0
#define PGP_signature_subpacket_is_critical 0x80
#define PGP_hardcoded_timestamp 0x58606060L
#define PGP_ed25519_oid "\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01"
#define PGP_ed25519_oid_size 9
#define PGP_public_file_name "/public.asc"
#define PGP_secret_file_name "/secret.asc"

typedef enum { PUBLIC_KEY, PRIVATE_KEY } PGP_key_type_t;

typedef struct __attribute__((__packed__)) pkt_header
{
    uint8_t length_type : 2; // codes for length field size; 0 is for single-octet length
    uint8_t packet_tag  : 4;
    uint8_t new_format  : 1;
    uint8_t always_one  : 1;
} pkt_header;

static uint16_t mpi_len(unsigned char msb)
{
    // This function takes the most significant byte and
    // returns (256 minus count of leading unset bits)
    // The libgcrypt MPI format prefixes big-endian integers with a uint16 specifying the
    // number of bits required to represent the integer.
    // We could hardcode "256", but that eveals our keys as being made by passphrase-identity,
    // so we have to adhere to the bit-counting MPI encoding that libgcrypt uses.
    uint16_t bits_not_set = 0;
    for(int c=0x80; ~msb & c; c>>=1 )
    {
        bits_not_set++;
    }
    return 256 - bits_not_set;
}

static bool crc24_bytes(unsigned char *octets, size_t len, uint8_t output[3])
{
    // Adapted from 6.1 An Implementation of the CRC-24 in "C"
    // https://tools.ietf.org/html/rfc4880#section-6.1

    if(NULL == octets || NULL == output || 0 == len)
        return false;

    int32_t crc = 0xB704CEL;

    while (len--)
    {
        crc ^= (*octets++) << 16;
        for (int i = 0; i < 8; i++)
        {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= 0x1864CFBL;
        }
    }

    crc = htonl(crc & 0xffffff);
    output[0] = (crc >>= 8) & 0xff;
    output[1] = (crc >>= 8) & 0xff;
    output[2] = (crc >>= 8) & 0xff;

    return true;
}

static struct buffer * openpgp_encode_armor(const struct buffer *input, PGP_key_type_t key_type)
{
    // 6. Radix-64 Conversions:
    // https://tools.ietf.org/html/rfc4880#section-6

    // "OpenPGP's Radix-64 encoding is composed of two parts: a base64
    // encoding of the binary data and a checksum.  The base64 encoding is
    // identical to the MIME base64 content-transfer-encoding [RFC2045]."

    bool ok = true;

    struct buffer * b64 = NULL;
    struct buffer * crc_raw = NULL;
    struct buffer * crc_b64 = NULL;
    struct buffer * output_buf = NULL;
    buffer_writer_t * output = NULL;

    if(NULL == input)
        goto error;

    // When OpenPGP encodes data into ASCII Armor, it puts specific headers
    // around the Radix-64 encoded data, so OpenPGP can reconstruct the data
    // later.  An OpenPGP implementation MAY use ASCII armor to protect raw
    // binary data.  OpenPGP informs the user what kind of data is encoded
    // in the ASCII armor through the use of the headers.

    ok &= buffer_base64_encode(input, &b64);

    output_buf = buffer_new(buffer_size(b64) + 400);
    output = buffer_writer_new(output_buf);
    if(NULL == output) goto error;

    crc_raw = buffer_new(3);
    if(NULL == crc_raw) goto error;
    ok &= crc24_bytes(input->data, input->size, crc_raw->data);
    ok &= buffer_base64_encode(crc_raw, &crc_b64);

    if(!ok) goto error;

    // - An Armor Header Line, appropriate for the type of data

    ok &= buffer_writer_write_asciiz(output, "-----BEGIN PGP ");
    if(PUBLIC_KEY == key_type)
        ok &= buffer_writer_write_asciiz(output, "PUBLIC");
    if(PRIVATE_KEY == key_type)
        ok &= buffer_writer_write_asciiz(output, "PRIVATE");
    ok &= buffer_writer_write_asciiz(output, " KEY BLOCK-----\n");

    // Blatantly lie about our user-agent:
    ok &= buffer_writer_write_asciiz(output, "Version: GnuPG v2\n\n");

    // Note that line lengths of the "Radix 64" (aka Base64) flavour specified is 76,
    // but we use 64 to be as similar to GnuPG as possible.
    // "6.3. Encoding Binary in Radix-64" (bottom paragraph):
    // https://tools.ietf.org/html/rfc4880#section-6.3

    ok &= buffer_writer_write_asciiz_with_linewrapping(output, (const char *) b64->data, 64);

    if(ok && '\n' != output->buffer->data[output->write_offset-1])
    {
        ok &= buffer_writer_write_asciiz(output, "\n");
    }

    ok &= buffer_writer_write_value(output, crc_b64->data, crc_b64->size);
    ok &= buffer_writer_write_asciiz(output, "\n");

    ok &= buffer_writer_write_asciiz(output, "-----END PGP ");
    if(PUBLIC_KEY == key_type)
        ok &= buffer_writer_write_asciiz(output, "PUBLIC");
    if(PRIVATE_KEY == key_type)
        ok &= buffer_writer_write_asciiz(output, "PRIVATE");
    ok &= buffer_writer_write_asciiz(output, " KEY BLOCK-----\n");

    goto cleanup;

    error:
    ok = false;

    cleanup:

    if(ok)
    {
        output_buf->size = output->write_offset;
    }else
    {
        buffer_free(output_buf);
        output_buf = NULL;
    }

    buffer_free(b64);
    buffer_free(crc_raw);
    buffer_free(crc_b64);
    buffer_writer_free(output);

    return output_buf;
}

static bool openpgp_keyid_from_profile(const struct profile_t * profile, char keyid[8])
{
    // TODO reference rfc 4880 spec section
    // loosely based on
    // gnupg2: g10/keyid.c:keyid_from_pk()
    // basically this is the rightmost 8 bytes of the sha1sum of
    // the output of g10/keyid.c:hash_public_key()

    if(NULL == profile || NULL == keyid)
    {
        return false;
    }

    struct buffer *tmp_buf = NULL;
    buffer_writer_t *buf  = NULL;

    bool ok = true;

    // version+time+pk_algo + oid_len+oid + mpi_bits+curve_flags+point_A
    const size_t msg_length = 1+4+1 + 1+1+strlen(PGP_ed25519_oid) + 1+1+32;

    // length including header: magic_uint8 + len_uint16 + msg_length
    tmp_buf = buffer_new(1+2 + msg_length);
    buf = buffer_writer_new(tmp_buf);

    // TODO "CTB" magic aka signature type /header type
    ok &= buffer_writer_write_uint8(buf, 0x99);
    // length of this pkt (not including the header):
    ok &= buffer_writer_write_uint16(buf, msg_length);

    // openpgp format version:
    ok &= buffer_writer_write_uint8(buf, 0x04);

    // timestamp
    ok &= buffer_writer_write_uint32(buf, PGP_hardcoded_timestamp);

    // pubkey algo: https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04#section-8
    ok &= buffer_writer_write_uint8(buf, 0x16);

    ok &= buffer_writer_write_uint8(buf, strlen(PGP_ed25519_oid));
    ok &= buffer_writer_write_asciiz(buf, PGP_ed25519_oid);

    // write public key. see comments in openpgp_fill_public_key for details
    ok &= buffer_writer_write_uint16(buf, 0x0107);
    ok &= buffer_writer_write_uint8(buf, 0x40);
    ok &= buffer_writer_write_value(buf, profile->openpgp_public, sizeof(profile->openpgp_public));

    SHA1Context sha1_ctx;
    uint8_t pk_hash[SHA1HashSize];

    ok &= shaSuccess == SHA1Reset(&sha1_ctx);
    if(!ok) goto cleanup;
    ok &= shaSuccess == SHA1Input(&sha1_ctx, tmp_buf->data, tmp_buf->size);
    if(!ok) goto cleanup;
    ok &= shaSuccess == SHA1Result(&sha1_ctx, pk_hash);
    if(!ok) goto cleanup;

    memcpy(keyid, pk_hash+sizeof(pk_hash)-8, 8);
    memcpy(keyid, pk_hash+12, 8);

    cleanup:
    buffer_free(tmp_buf);
    buffer_writer_free(buf);

    sodium_memzero(&sha1_ctx, sizeof sha1_ctx);
    sodium_memzero(&pk_hash, sizeof pk_hash);

    return ok;
}

static struct buffer * openpgp_transferable_public_or_secret_key_packet(const profile_t *profile, PGP_key_type_t key_type)
{
    // 5.5.1.1.  Public-Key Packet (Tag 6)
    // 5.5.1.3.  Secret-Key Packet (Tag 5)
    struct buffer *key_packet = NULL;
    struct buffer_writer *pkp_w = NULL;

    bool ok = true;

/*      sizeof(uint8_t)  // Version
      + sizeof(uint32_t) // Timestamp
      + sizeof(uint8_t)  // Public-key algorithm
      + sizeof(uint8_t)  // Length of curve point
      + PGP_ed25519_oid_size // Curve point
      + sizeof(uint16_t) // MPI length field for EdDSA "A"
      + sizeof(uint8_t)  // point compression type
      + sizeof profile->openpgp_public
      + (PUBLIC_KEY == key_type ? 0 : (
            sizeof(uint8_t) // "string-to-key" usage AKA "DO YOU ENCRYPT?!"
          + sizeof(uint16_t) // MPI length field for EdDSA "ENC(X,Y)"
          + sizeof(profile->openpgp_secret) // the seed "d" for EdDSA secret key
          + sizeof(uint16_t) // the "sum all the bytes" checksum"
        )
      );
*/
    #define pgp_public_packet_msg_length \
      ( sizeof(uint8_t) \
      + sizeof(uint32_t) \
      + sizeof(uint8_t) \
      + sizeof(uint8_t) \
      + PGP_ed25519_oid_size \
      + sizeof(uint16_t) \
      + sizeof(uint8_t) \
      + sizeof(profile->openpgp_public) \
      )
    #define pgp_private_packet_msg_length \
      ( \
        pgp_public_packet_msg_length \
      + sizeof(uint8_t) \
      + sizeof(uint16_t) \
      + sizeof(profile->openpgp_secret) \
      + sizeof(uint16_t) \
      )

    const uint16_t msg_length = (PUBLIC_KEY == key_type) ? pgp_public_packet_msg_length : pgp_private_packet_msg_length;

    key_packet = buffer_new(sizeof(struct pkt_header)+sizeof(uint8_t)+msg_length);
    pkp_w = buffer_writer_new(key_packet);

    struct pkt_header packet_header =
    {
        .always_one  = 1,
        .new_format  = 0,
        .packet_tag  = 0,
        .length_type = PGP_single_octet_length
    };

    if(PUBLIC_KEY == key_type)
        // 5.5.1.1.  Public-Key Packet (Tag 6)
        packet_header.packet_tag = 6;

    if(PRIVATE_KEY == key_type)
        // 5.5.1.3.  Secret-Key Packet (Tag 5)
        packet_header.packet_tag = 5;

    ok &= buffer_writer_write_value(pkp_w, &packet_header, sizeof(packet_header));

    // length of this packet:
    assert(msg_length < 192); // TODO
    ok &= buffer_writer_write_uint8(pkp_w, msg_length);

    // see: 5.5.2.  Public-Key Packet Formats:

    // version: (version 4)
    ok &= buffer_writer_write_uint8(pkp_w, 0x04);

    // timestamp (created):
    ok &= buffer_writer_write_uint32(pkp_w, PGP_hardcoded_timestamp);

    // public-key algorithm of key; that is EdDSA, see:
    // https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04#section-8
    // and https://tools.ietf.org/html/rfc6637
    // and eventually https://tools.ietf.org/html/rfc4880#section-9.1
    ok &= buffer_writer_write_uint8(pkp_w, 0x16);

    // length of curve point / OID (in bytes):
    ok &= buffer_writer_write_uint8(pkp_w, 9);
    // Ed25519 OID: https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04#section-6
    ok &= buffer_writer_write_value(pkp_w, PGP_ed25519_oid, strlen(PGP_ed25519_oid));

    // MPI of an EC point representing a public key Q, length in bits (=0x107=263=256+7)
    // equivalent to: mpi_len(0x40) + 8
    ok &= buffer_writer_write_uint16(pkp_w, 0x0107);

    // Point Compression flag byte: 0x40  Native point format of the curve follows:
    // see https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04#appendix-B
    ok &= buffer_writer_write_uint8(pkp_w, 0x40);

    // public key element "Q"
    ok &= buffer_writer_write_value(pkp_w, profile->openpgp_public, sizeof profile->openpgp_public);

    if(PRIVATE_KEY == key_type)
    {
        // Secret-Key Packet Formats https://tools.ietf.org/html/rfc4880#section-5.5.3

        // for more pointers to what is going on here I suggest looking at gnupg src:
        // g10/packet.h:struct seckey_info
        // g10/import.c:transfer_secret_keys()
        // g10/export.c:transfer_format_to_openpgp() - validation stub
        // agent/command.c:cmd_import_key() - where it actually imports stuff
        // agent/cvt-xx : do_unprotect() - where the checksum/"actual_csum" is calculated

        // "One octet indicating string-to-key usage conventions.
        //  Zero indicates that the secret-key data is not encrypted.
        //  255 or 254 indicates that a string-to-key specifier is being given.
        //  Any other value is a symmetric-key encryption algorithm identifier.

        ok &= buffer_writer_write_uint8(pkp_w, 0x00);

        // from gnupg src: Append the secret key element D.
        // NB this is what libsodium calls a "seed" - GPG hashes it
        //    every time it makes a signature

        // from https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-04#section-4
        // The following algorithm specific packets are added to Section 5.5.3
        //   of [RFC4880], "Secret-Key Packet Formats", to support EdDSA.
        //   Algorithm-Specific Fields for EdDSA keys:
        //   o  an MPI of an integer representing the secret key, which is a
        //      scalar of the public EC point.

        uint16_t mpi_length = mpi_len(*profile->openpgp_secret);

        ok &= buffer_writer_write_uint16(pkp_w, mpi_length);

        ok &= buffer_writer_write_value(pkp_w, profile->openpgp_secret, sizeof(profile->openpgp_secret));

        // If the string-to-key usage octet is zero or 255, then a two-octet
        // checksum of the plaintext of the algorithm-specific portion (sum
        // of all octets, mod 65536):
        if(ok)
        {
            uint16_t checksum = 0;
            checksum += mpi_length & 0xff;
            checksum += mpi_length >> 8;
            for(uint8_t i = 0; i < 32; i++)
            {
                checksum += *(i + profile->openpgp_secret);
            }
            ok &= buffer_writer_write_uint16(pkp_w, checksum);
        }
    }

    if(ok)
    {
        // limit size so we can rely on ->size
        if(key_packet->size > pkp_w->write_offset)
            key_packet->size = pkp_w->write_offset;
    }
    else
    {
        buffer_free(key_packet);
        key_packet = NULL;
    }

    buffer_writer_free(pkp_w);

    return key_packet;
}

static struct buffer * openpgp_fill_key(const profile_t * profile, PGP_key_type_t key_type)
{
    if(NULL == profile
    || NULL == profile->username)
        return NULL;

    struct buffer *public_key_packet = NULL;

    struct buffer *uid_packet = NULL;
    struct buffer_writer *uid_w = NULL;

    struct buffer *headless_signature_packet = NULL;
    buffer_writer_t *sig_w = NULL;

    struct buffer *signature_unhashed_subpacket = NULL;
    buffer_writer_t *unhashed_w = NULL;

    struct buffer *output = NULL;
    buffer_writer_t *output_w = NULL;

    struct buffer *tobehashed = NULL;
    buffer_writer_t * tbh = NULL;

    struct buffer * sig_subpacket = NULL;
    buffer_writer_t * sig_subpacket_w = NULL;

    bool ok = true;

    struct pkt_header packet_header =
    {
        .always_one  = 1,
        .new_format  = 0,
        .packet_tag  = 0,
        .length_type = PGP_single_octet_length
    };

////// 5.5.1.1.  Public-Key Packet (Tag 6)

    public_key_packet = openpgp_transferable_public_or_secret_key_packet(profile, key_type);
    if(NULL == public_key_packet)
    {
        ok = false;
        goto cleanup;
    }

////// rfc 4880 section 5.11: User ID Packet (tag 13):
    uid_packet = buffer_new(sizeof(packet_header) + sizeof(uint8_t) + strlen(profile->username));

    uid_w = buffer_writer_new(uid_packet);

    packet_header.packet_tag = 13;
    ok &= buffer_writer_write_value(uid_w, &packet_header, sizeof(packet_header));
    ok &= buffer_writer_write_uint8(uid_w, strlen(profile->username));
    ok &= buffer_writer_write_value(uid_w, profile->username, strlen(profile->username));

////// rfc4880: Version 4 Signature Packet Format: https://tools.ietf.org/html/rfc4880#section-5.2.3
    // see gnupg2 source code: g10/sign.c:make_keysig_packet()
    //                         g10/parse-packet.c:parse_signature()
    //                         g10/:do_signature()
    // TODO agent_pksign
    // also see the PKT_signature struct

    headless_signature_packet = buffer_new(1000);

    sig_w = buffer_writer_new(headless_signature_packet);

    // version: (version 4)
    // gnupg2: sig->sig_version
    ok &= buffer_writer_write_uint8(sig_w, 0x04);
    // signature class: 0x13: Positive certification of a User ID and Public-Key packet.
    // see https://tools.ietf.org/html/rfc4880#section-5.2.1
    // gnupg2: sig->sig_class
    ok &= buffer_writer_write_uint8(sig_w, 0x13);
    // See comment about "public-key algorithm of key" (but basically - ed25519):
    // gnupg2: sig->sig_pubkey_algo
    ok &= buffer_writer_write_uint8(sig_w, 0x16);
    // Hashing-algorithm: SHA256 (see https://tools.ietf.org/html/rfc4880#section-9.4):
    // gnupg2: sig->sig_digest_algo
    ok &= buffer_writer_write_uint8(sig_w, 0x08);

  //// 5.2.3.1.  Signature Subpacket Specification (zero or more subpackets)
    // - subpacket length (1; 2; 5 octets) (if <192: 1)
    // - subpacket type (1 octet)

    //   Bit 7 of the subpacket type is the "critical" bit.  If set, it
    //   denotes that the subpacket is one that is critical for the evaluator
    //   of the signature to recognize.  If a subpacket is encountered that is
    //   marked critical but is unknown to the evaluating software, the
    //   evaluator SHOULD consider the signature to be in error.

    sig_subpacket = buffer_new(1000);
    sig_subpacket_w = buffer_writer_new(sig_subpacket);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x05);
    // 2: Signature Creation Time: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
    // see build_sig_subpkt_from_sig(), build_sig_subpkt( sig, SIGSUBPKT_SIG_CREATED, ..)
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);
    // timestamp:
    ok &= buffer_writer_write_uint32(sig_subpacket_w, PGP_hardcoded_timestamp);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);
    // 27: Key Flags: https://tools.ietf.org/html/rfc4880#section-5.2.3.21
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x1b);
    // flags:
    //       0x01 - This key may be used to certify other keys.
    //       0x02 - This key may be used to sign data.
    // NOT SET: 0x04 - This key may be used to encrypt communications.
    //       0x20 - This key may be used for authentication.
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x23);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x05);
    // 11 = Preferred Symmetric Algorithms: https://tools.ietf.org/html/rfc4880#section-5.2.3.7
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x0b);
    // list of legal values: https://tools.ietf.org/html/rfc4880#section-9.2
    // 9 - AES with 256-bit key:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x09);
    // 8 - AES with 192-bit key:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x08);
    // 7 - AES with 128-bit key:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x07);
    // 2 - TripleDES (DES-EDE, [SCHNEIER] [HAC] 168 bit key derived from 192)
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x06);
    // 21 = Preferred Hash Algorithms: https://tools.ietf.org/html/rfc4880#section-5.2.3.8
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x15);
    // list of legal values: https://tools.ietf.org/html/rfc4880#section-9.2
    // 8  - SHA256:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x08);
    // 9  - SHA384:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x09);
    // 10 - SHA512:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x0a);
    // 11 - SHA224:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x0b);
    // 2  - SHA-1:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x04);
    // 22 = Preferred Compression Algorithms: https://tools.ietf.org/html/rfc4880#section-5.2.3.9
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x16);
    // list of legal values:https://tools.ietf.org/html/rfc4880#section-9.3
    // 2 - ZLIB rfc 1950
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);
    // 3 - Bzip2
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x03);
    // 1 - ZIP rfc 1951
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x01);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02);
    // 30 = Features: https://tools.ietf.org/html/rfc4880#section-5.2.3.24
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x1e);
    // 0x01 - Modification Detection (packets 18 and 19):
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x01);

    // length:
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x02); // 26
    // 23 = Key Server Preferences: https://tools.ietf.org/html/rfc4880#section-5.2.3.17
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x17);
    // First octet: 0x80 = No-modify
    // the key holder requests that this key only be modified or updated
    // by the key holder or an administrator of the key server.
    ok &= buffer_writer_write_uint8(sig_subpacket_w, 0x80);

  //// UNHASHED SUBPACKET DATA:

    signature_unhashed_subpacket = buffer_new(1000);

    unhashed_w = buffer_writer_new(signature_unhashed_subpacket);

    // - Two-octet scalar octet count for the following unhashed subpacket
    //   data.  Note that this is the length in octets of all of the
    //   unhashed subpackets; a pointer incremented by this number will
    //   skip over the unhashed subpackets.
    ok &= buffer_writer_write_uint16(unhashed_w, 10);

    // subpacket length:
    ok &= buffer_writer_write_uint8(unhashed_w, 9);
    // 16 = Issuer: https://tools.ietf.org/html/rfc4880#section-5.2.3.5
    ok &= buffer_writer_write_uint8(unhashed_w, 0x10);
    // 8-octets: The OpenPGP Key ID of the key issuing the signature.
    //uint8_t pk_keyid[8];
    char pk_keyid[8];
    sodium_memzero(&pk_keyid, sizeof pk_keyid);
    ok &= openpgp_keyid_from_profile(profile, pk_keyid);
    if(!ok) goto cleanup;

    ok &= buffer_writer_write_value(unhashed_w, pk_keyid, sizeof pk_keyid);

  //// continue the signature packet (this marks end of unhashed subpacket data)
    if(!ok) goto cleanup;

    // Two-octet scalar octet count for the following HASHED subpacket data.
    ok &= buffer_writer_write_uint16(sig_w, sig_subpacket_w->write_offset);

    ok &= buffer_writer_write_buffer(sig_w, sig_subpacket_w);

    unsigned char signature_hash[crypto_hash_sha256_BYTES];
    tobehashed = buffer_new(1000);
    tbh = buffer_writer_new(tobehashed);

    // see 5.2.4 Computing Signatures - https://tools.ietf.org/html/rfc4880#section-5.2.4
    // signature_type ("over a key")
    ok &= buffer_writer_write_uint8(tbh, 0x99);
    // two-octet length of the public key packet body
    ok &= buffer_writer_write_uint16(tbh, pgp_public_packet_msg_length);

    // - hash the public key certificate: hash_public_key()
    ok &= buffer_writer_write_value(tbh, 2+public_key_packet->data, pgp_public_packet_msg_length);

    // - hash the uid: hash_uid()
    // "A V4 certification hashes the constant 0xB4 for User ID certifications"
    ok &= buffer_writer_write_uint8(tbh, 0xB4);
    // "followed by a four-octet number giving the length of the User ID"
    ok &= buffer_writer_write_uint32(tbh, *(1+uid_w->buffer->data));
    ok &= buffer_writer_write_value(tbh, 2+uid_w->buffer->data, uid_w->write_offset-2);

    // - hash this pkt so far: first part of hash_sigversion_to_magic()
    ok &= buffer_writer_write_buffer(tbh, sig_w);

    crypto_hash_sha256_state sha256_state;

    // construct the magic part two of hash_sigversion_to_magic(): (wtf openpgp)
    // "V4 signatures also hash in a final trailer of six octets" ...
    // sig->version
    ok &= buffer_writer_write_uint8(tbh, 0x04);
    // len of hashed part of signature packet so far,
    // in the OpenPGP 5-octet length format:
    //   if the 1st octet = 255, then
    //       lengthOfLength = 5
    //       subpacket length = [four-octet scalar starting at 2nd_octet]
    ok &= buffer_writer_write_uint8(tbh, 0xFF);
    ok &= buffer_writer_write_uint32(tbh, sig_w->write_offset);

    ok &= 0== crypto_hash_sha256_init(&sha256_state);
    if(!ok) goto cleanup;
    ok &= 0== crypto_hash_sha256_update(&sha256_state, tobehashed->data, tbh->write_offset);
    if(!ok) goto cleanup;
    ok &= 0== crypto_hash_sha256_final(&sha256_state, signature_hash);
    if(!ok) goto cleanup;

  //// now that we are done computing the hash, add the un-MAC'ed subpackets:

    ok &= buffer_writer_write_buffer(sig_w, unhashed_w);

    // - Two-octet field holding left 16 bits of signed hash value.
    // NB: "signed hash value" AKA "ecc_verify data:" field
    //     when running gpg --debug-level guru --import
    ok &= buffer_writer_write_uint8(sig_w, signature_hash[0]);
    ok &= buffer_writer_write_uint8(sig_w, signature_hash[1]);

    // - "One or more multiprecision integers comprising the signature."
    // in Ed25519 EdDSA it's the R and S values from
    // https://tools.ietf.org/html/rfc8032#section-3.3
    // so this is where we pray that libsodium implements this:
    //  Let R = [r]B and S = (r + H(ENC(R) || ENC(A) || PH(M)) * s) mod L
    // and that we use this encoding: https://tools.ietf.org/html/rfc8032#section-3.1

    struct __attribute__((__packed__))
    {
        char r[32];
        char s[32];
    } ed25519_sig;

    // TODO consider using crypto_sign_ed25519_sk_to_seed() instead
    unsigned char *tmp_secret = sodium_malloc(64);
    ok &= NULL != tmp_secret;
    if(!ok) goto cleanup;

    ok &= 0== crypto_sign_ed25519_seed_keypair(32+tmp_secret, tmp_secret, profile->openpgp_secret);
    if(!ok) goto zero_secret;

    ok &= 0== crypto_sign_ed25519_detached((unsigned char *)&ed25519_sig, NULL, signature_hash, sizeof signature_hash, tmp_secret);

    zero_secret:
    sodium_free(tmp_secret);
    if(!ok) goto cleanup;

    // size of EdDSA "R" in bits: https://tools.ietf.org/html/rfc6637#section-6
    ok &= buffer_writer_write_uint16(sig_w, mpi_len(*ed25519_sig.r));
    ok &= buffer_writer_write_value(sig_w, ed25519_sig.r, sizeof ed25519_sig.r);

    // size of EdDSA "S" in bits:
    ok &= buffer_writer_write_uint16(sig_w, mpi_len(*ed25519_sig.s));
    ok &= buffer_writer_write_value(sig_w, ed25519_sig.s, sizeof ed25519_sig.s);

////// assemble our three packets into a single buffer:

    output = buffer_new(
          2 // make space for the sig_w two-byte header
        + buffer_size(public_key_packet)
        + uid_w->write_offset
        + sig_w->write_offset
    );

    output_w = buffer_writer_new(output);

    ok &= buffer_writer_write_value(output_w, public_key_packet->data, buffer_size(public_key_packet));
    ok &= buffer_writer_write_buffer(output_w, uid_w);

  //// give headless_signature_packet a head
    packet_header.packet_tag = 2;
    ok &= buffer_writer_write_value(output_w, &packet_header, sizeof(packet_header));
    // one-octet pkt length:
    // assert(192 > buffer_size(headless_signature_packet));
    ok &= buffer_writer_write_uint8(output_w, sig_w->write_offset);
    ok &= buffer_writer_write_buffer(output_w, sig_w);

    cleanup:
    // - the writer for public_key_packet gets cleaned up in its own function
    buffer_writer_free(uid_w);
    buffer_writer_free(sig_w);
    buffer_writer_free(output_w);
    buffer_writer_free(unhashed_w);
    buffer_writer_free(tbh);

    buffer_free(public_key_packet);
    buffer_free(uid_packet);
    buffer_free(headless_signature_packet);
    buffer_free(sig_subpacket);
    buffer_free(signature_unhashed_subpacket);
    buffer_free(tobehashed);

    sodium_memzero(signature_hash, sizeof(signature_hash));
    sodium_memzero(&sha256_state, sizeof(sha256_state));
    sodium_memzero(&ed25519_sig, sizeof(ed25519_sig));

    if(ok)
    {
       return output;
    }

    buffer_free(output);
    return NULL;
}

    // Transferable Secret Keys:
    // https://tools.ietf.org/html/rfc4880#section-11.2
    // The format of a transferable
    // secret key is the same as a transferable public key except that
    // secret-key and secret-subkey packets are used instead of the public
    // key and public-subkey packets.

    // 5.5.1.3.  Secret-Key Packet (Tag 5)
    //   A Secret-Key packet contains all the information that is found in a
    //   Public-Key packet, including the public-key material, but also
    //   includes the secret-key material after all the public-key fields.

        // Algorithm-Specific Fields for EdDSA keys:
        //   o  an MPI of an integer representing the secret key, which is a
        //      scalar of the public EC point.

    // 5.5.1.4.  Secret-Subkey Packet (Tag 7)

    //   A Secret-Subkey packet (tag 7) is the subkey analog of the Secret
    //   Key packet and has exactly the same format.

bool openpgp_write(const char *output_directory, const struct profile_t *profile)
{
    if(NULL == profile || NULL == output_directory)
        return false;

    // since we're going to display error messages, reset errno to avoid
    // describing previous errors:
    errno = 0;

    FILE * fh = NULL;
    bool ok = true;

    struct buffer * public_data = NULL;
    struct buffer * secret_data = NULL;
    struct buffer * ascii_public_data = NULL;
    struct buffer * ascii_secret_data = NULL;
    char * public_path = NULL;
    char * secret_path = NULL;

    public_data = openpgp_fill_key(profile, PUBLIC_KEY);
    ascii_public_data = openpgp_encode_armor(public_data, PUBLIC_KEY);
    if(NULL == ascii_public_data) goto error;

    public_path = malloc(strlen(output_directory) + strlen(PGP_public_file_name) + 1);
    if(NULL == public_path) goto error;
    strcpy(public_path, output_directory);
    strcat(public_path, PGP_public_file_name);

    fh = fopen(public_path, "wcx");
    if(NULL == fh) goto error;
    if(1 != fwrite(ascii_public_data->data, ascii_public_data->size, 1, fh)) goto error;
    if(0 != fclose(fh)) goto error;

    secret_data = openpgp_fill_key(profile, PRIVATE_KEY);
    ascii_secret_data = openpgp_encode_armor(secret_data, PRIVATE_KEY);
    if(NULL == ascii_secret_data) goto error;

    secret_path = malloc(strlen(output_directory) + strlen(PGP_secret_file_name) + 1);
    if(NULL == secret_path) goto error;
    strcpy(secret_path, output_directory);
    strcat(secret_path, PGP_secret_file_name);

    fh = fopen(secret_path, "wcx");
    if(NULL == fh) goto error;
    if(1 != fwrite(ascii_secret_data->data, ascii_secret_data->size, 1, fh)) goto error;
    if(0 != fclose(fh)) goto error;

    goto cleanup;

    error:
    ok = false;

    if(errno)
        perror("OpenPGP error");

    cleanup:
    buffer_free(public_data);
    buffer_free(secret_data);
    buffer_free(ascii_public_data);
    buffer_free(ascii_secret_data);
    free(public_path);
    free(secret_path);

    return ok;
}
