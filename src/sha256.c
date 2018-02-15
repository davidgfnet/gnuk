/*
 * sha256.c -- Compute SHA-256 hash
 *
 * Just for little endian architecture.
 *
 * Code taken from:
 *  http://gladman.plushost.co.uk/oldsite/cryptography_technology/sha/index.php
 *
 *  File names are sha2.c, sha2.h, brg_types.h, brg_endian.h
 *  in the archive sha2-07-01-07.zip.
 *
 * Code is modified in the style of PolarSSL API.
 *
 * See original copyright notice below.
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 01/08/2005
*/

#include <string.h>
#include <stdint.h>
#include "sha256.h"
#include "sha-common.h"

#define SHA256_MASK (SHA256_BLOCK_SIZE - 1)

static void memcpy_output_bswap32 (unsigned char *dst, const uint32_t *p)
{
  int i;
  uint32_t q = 0;

  for (i = 0; i < 32; i++)
    {
      if ((i & 3) == 0)
	q = __builtin_bswap32 (p[i >> 2]); /* bswap32 is GCC extention */
      dst[i] = q >> ((i & 3) * 8);
    }
}

#define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))

#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

/* round transforms for SHA256 compression functions */
#define vf(n,i) v[(n - i) & 7]

#define hf(i) (p[i & 15] += \
    g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]))

#define v_cycle0(i)                                 \
    p[i] = __builtin_bswap32 (p[i]);                \
    vf(7,i) += p[i] + k_0(i)                        \
    + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
    vf(3,i) += vf(7,i);                             \
    vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define v_cycle(i, j)                               \
    vf(7,i) += hf(i) + k_0(i+j)                     \
    + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
    vf(3,i) += vf(7,i);                             \
    vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define v_cyclea(i, idx)                            \
    vf(7,i) += hf(i) + k_0(idx)                     \
    + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
    vf(3,i) += vf(7,i);                             \
    vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define s_0(x)  (rotr32((x),  2) ^ rotr32((x), 13) ^ rotr32((x), 22))
#define s_1(x)  (rotr32((x),  6) ^ rotr32((x), 11) ^ rotr32((x), 25))
#define g_0(x)  (rotr32((x),  7) ^ rotr32((x), 18) ^ ((x) >>  3))
#define g_1(x)  (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))
#define k_0     k256

void
sha256_process (sha256_context *ctx)
{
  uint32_t i;
  uint32_t *p = ctx->wbuf;
  uint32_t v[8];

  memcpy (v, ctx->state, 8 * sizeof (uint32_t));

  #ifdef HASH_OPTIMIZE_SIZE
  for (i = 0; i < 16; i++) {
    v_cycle0(i);
  }

  for (i = 16; i < 64; i++)
    {
      uint32_t si = i & 15;
      v_cyclea (si, i);
    }
  #else
  v_cycle0 ( 0); v_cycle0 ( 1); v_cycle0 ( 2); v_cycle0 ( 3);
  v_cycle0 ( 4); v_cycle0 ( 5); v_cycle0 ( 6); v_cycle0 ( 7);
  v_cycle0 ( 8); v_cycle0 ( 9); v_cycle0 (10); v_cycle0 (11);
  v_cycle0 (12); v_cycle0 (13); v_cycle0 (14); v_cycle0 (15);

  for (i = 16; i < 64; i += 16)
    {
      v_cycle ( 0, i); v_cycle ( 1, i); v_cycle ( 2, i); v_cycle ( 3, i);
      v_cycle ( 4, i); v_cycle ( 5, i); v_cycle ( 6, i); v_cycle ( 7, i);
      v_cycle ( 8, i); v_cycle ( 9, i); v_cycle (10, i); v_cycle (11, i);
      v_cycle (12, i); v_cycle (13, i); v_cycle (14, i); v_cycle (15, i);
    }
  #endif

  for (unsigned i = 0; i < 8; i++)
    ctx->state[i] += v[i];
}

void
sha256_update (sha256_context *ctx, const unsigned char *input,
               unsigned int ilen)
{
  uint32_t left = (ctx->total[0] & SHA256_MASK);
  uint32_t fill = SHA256_BLOCK_SIZE - left;

  ctx->total[0] += ilen;
  if (ctx->total[0] < ilen)
    ctx->total[1]++;

  while (ilen >= fill)
    {
      memcpy (((unsigned char*)ctx->wbuf) + left, input, fill);
      sha256_process (ctx);
      input += fill;
      ilen -= fill;
      left = 0;
      fill = SHA256_BLOCK_SIZE;
    }

  memcpy (((unsigned char*)ctx->wbuf) + left, input, ilen);
}

void
sha256_finish (sha256_context *ctx, unsigned char output[32])
{
  uint32_t last = (ctx->total[0] & SHA256_MASK);

  ctx->wbuf[last >> 2] = __builtin_bswap32 (ctx->wbuf[last >> 2]);
  ctx->wbuf[last >> 2] &= 0xffffff80 << (8 * (~last & 3));
  ctx->wbuf[last >> 2] |= 0x00000080 << (8 * (~last & 3));
  ctx->wbuf[last >> 2] = __builtin_bswap32 (ctx->wbuf[last >> 2]);

  if (last > SHA256_BLOCK_SIZE - 9)
    {
      if (last < 60)
        ctx->wbuf[15] = 0;
      sha256_process (ctx);
      last = 0;
    }
  else
    last = (last >> 2) + 1;

  while (last < 14)
    ctx->wbuf[last++] = 0;

  ctx->wbuf[14] = __builtin_bswap32 ((ctx->total[0] >> 29) | (ctx->total[1] << 3));
  ctx->wbuf[15] = __builtin_bswap32 (ctx->total[0] << 3);
  sha256_process (ctx);

  memcpy_output_bswap32 (output, ctx->state);
  memset (ctx, 0, sizeof (sha256_context));
}

static const uint32_t initial_state[8] =
{
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void
sha256_start (sha256_context *ctx)
{
  ctx->total[0] = ctx->total[1] = 0;
  memcpy (ctx->state, initial_state, 8 * sizeof(uint32_t));
}

void
sha256 (const unsigned char *input, unsigned int ilen,
        unsigned char output[32])
{
  sha256_context ctx;

  sha256_start (&ctx);
  sha256_update (&ctx, input, ilen);
  sha256_finish (&ctx, output);
}
