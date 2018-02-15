/* sha_test.c
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "sha256.h"
#include "sha512.h"

#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64

typedef struct testVector {
    const char*  input;
    const char*  output;
    size_t inLen;
    size_t outLen;
} testVector;

void sha256_test()
{
    sha256_context sha;
    uint8_t   hash[SHA256_DIGEST_SIZE];

    testVector a, b, c;
    testVector test_sha[3];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "";
    a.output = "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9"
               "\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52"
               "\xb8\x55";
    a.inLen  = strlen(a.input);
    a.outLen = SHA256_DIGEST_SIZE;

    b.input  = "abc";
    b.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
               "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
               "\x15\xAD";
    b.inLen  = strlen(b.input);
    b.outLen = SHA256_DIGEST_SIZE;

    c.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    c.output = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
               "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
               "\x06\xC1";
    c.inLen  = strlen(c.input);
    c.outLen = SHA256_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;

    for (i = 0; i < times; ++i) {
        sha256((uint8_t*)test_sha[i].input, test_sha[i].inLen, hash);

        if (memcmp(hash, test_sha[i].output, SHA256_DIGEST_SIZE) != 0)
            exit(1);
    }

    /* BEGIN LARGE HASH TEST */ {
    uint8_t large_input[1024];
    const char* large_digest =
        "\x27\x78\x3e\x87\x96\x3a\x4e\xfb\x68\x29\xb5\x31\xc9\xba\x57\xb4"
        "\x4f\x45\x79\x7f\x67\x70\xbd\x63\x7f\xbf\x0d\x80\x7c\xbd\xba\xe0";

    sha256_start(&sha);
    for (i = 0; i < (int)sizeof(large_input); i++) {
        large_input[i] = (uint8_t)(i & 0xFF);
    }
    times = 100;
    for (i = 0; i < times; ++i)
        sha256_update(&sha, (uint8_t*)large_input, sizeof(large_input));

    sha256_finish(&sha, hash);
    if (memcmp(hash, large_digest, SHA256_DIGEST_SIZE) != 0)
        exit(1);
    } /* END LARGE HASH TEST */
}

void sha512_test(void)
{
    sha512_context sha;
    uint8_t   hash[SHA512_DIGEST_SIZE];

    testVector a, b, c;
    testVector test_sha[3];
    int times = sizeof(test_sha) / sizeof(struct testVector), i;

    a.input  = "";
    a.output = "\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80"
               "\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c"
               "\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87"
               "\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a"
               "\xf9\x27\xda\x3e";
    a.inLen  = strlen(a.input);
    a.outLen = SHA512_DIGEST_SIZE;

    b.input  = "abc";
    b.output = "\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41"
               "\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55"
               "\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3"
               "\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f"
               "\xa5\x4c\xa4\x9f";
    b.inLen  = strlen(b.input);
    b.outLen = SHA512_DIGEST_SIZE;

    c.input  = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhi"
               "jklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    c.output = "\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14"
               "\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88"
               "\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4"
               "\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b"
               "\x87\x4b\xe9\x09";
    c.inLen  = strlen(c.input);
    c.outLen = SHA512_DIGEST_SIZE;

    test_sha[0] = a;
    test_sha[1] = b;
    test_sha[2] = c;

    for (i = 0; i < times; ++i) {
        sha512((uint8_t*)test_sha[i].input, test_sha[i].inLen, hash);

        if (memcmp(hash, test_sha[i].output, SHA512_DIGEST_SIZE) != 0)
            exit(1);
    }

    // BEGIN LARGE HASH TEST
    uint8_t large_input[1024];
    const char* large_digest =
        "\x5a\x1f\x73\x90\xbd\x8c\xe4\x63\x54\xce\xa0\x9b\xef\x32\x78\x2d"
        "\x2e\xe7\x0d\x5e\x2f\x9d\x15\x1b\xdd\x2d\xde\x65\x0c\x7b\xfa\x83"
        "\x5e\x80\x02\x13\x84\xb8\x3f\xff\x71\x62\xb5\x09\x89\x63\xe1\xdc"
        "\xa5\xdc\xfc\xfa\x9d\x1a\x4d\xc0\xfa\x3a\x14\xf6\x01\x51\x90\xa4";

    for (i = 0; i < (int)sizeof(large_input); i++)
        large_input[i] = (uint8_t)(i & 0xFF);

    sha512_start(&sha);
    times = 100;
    for (i = 0; i < times; ++i)
        sha512_update(&sha, (uint8_t*)large_input, sizeof(large_input));

    sha512_finish(&sha, hash);
    if (memcmp(hash, large_digest, SHA512_DIGEST_SIZE) != 0)
        exit(1);
}

int main() {
    sha256_test();
    sha512_test();

    return 0;
}

