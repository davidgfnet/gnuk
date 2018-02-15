/*
 * sha512.c -- Compute SHA-512 hash (for little endian architecture).
 *
 * This module is written by gniibe, following the API of sha256.c.
 *
 * Copyright (C) 2014 Free Software Initiative of Japan
 * Author: NIIBE Yutaka <gniibe@fsij.org>
 *
 * This file is a part of Gnuk, a GnuPG USB Token implementation.
 *
 * Gnuk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gnuk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*
 * Reference:
 *
 * [1] FIPS PUB 180-4: Secure hash Standard (SHS), March, 2012.
 *
 */

#include <string.h>
#include <stdint.h>
#include "sha512.h"
#include "sha-common.h"

#define SHA512_MASK (SHA512_BLOCK_SIZE - 1)

static void memcpy_output_bswap64 (unsigned char dst[64], const uint64_t *p)
{
  int i;
  uint64_t q = 0;

  for (i = 0; i < 64; i++)
    {
      if ((i & 7) == 0)
	q = __builtin_bswap64 (p[i >> 3]); /* bswap64 is GCC extention */
      dst[i] = q >> ((i & 7) * 8);
    }
}

#define rotr64(x,n)   (((x) >> n) | ((x) << (64 - n)))

#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

/* round transforms for SHA512 compression functions */
#define vf(n,i) v[(n - i) & 7]

#define hf(i) (p[i & 15] += \
    g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]))

#define v_cycle0(i)                                 \
    p[i] = __builtin_bswap64 (p[i]);                \
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

#define s_0(x)  (rotr64((x), 28) ^ rotr64((x), 34) ^ rotr64((x), 39))
#define s_1(x)  (rotr64((x), 14) ^ rotr64((x), 18) ^ rotr64((x), 41))
#define g_0(x)  (rotr64((x),  1) ^ rotr64((x),  8) ^ ((x) >>  7))
#define g_1(x)  (rotr64((x), 19) ^ rotr64((x), 61) ^ ((x) >>  6))
#define k_0     k512

void
sha512_process (sha512_context *ctx)
{
  uint32_t i;
  uint64_t *p = ctx->wbuf;
  uint64_t v[8];

  memcpy (v, ctx->state, 8 * sizeof (uint64_t));

  #ifdef HASH_OPTIMIZE_SIZE
  for (i = 0; i < 16; i++) {
    v_cycle0(i);
  }
  for (i = 16; i < 80; i++) {
    uint32_t si = i & 15;
    v_cyclea(si, i);
  }
  #else
  v_cycle0 ( 0); v_cycle0 ( 1); v_cycle0 ( 2); v_cycle0 ( 3);
  v_cycle0 ( 4); v_cycle0 ( 5); v_cycle0 ( 6); v_cycle0 ( 7);
  v_cycle0 ( 8); v_cycle0 ( 9); v_cycle0 (10); v_cycle0 (11);
  v_cycle0 (12); v_cycle0 (13); v_cycle0 (14); v_cycle0 (15);

  for (i = 16; i < 80; i += 16)
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
sha512_update (sha512_context *ctx, const unsigned char *input,
               unsigned int ilen)
{
  uint32_t left = (ctx->total[0] & SHA512_MASK);
  uint32_t fill = SHA512_BLOCK_SIZE - left;

  ctx->total[0] += ilen;
  if (ctx->total[0] < ilen)
    ctx->total[1]++;

  while (ilen >= fill)
    {
      memcpy (((unsigned char*)ctx->wbuf) + left, input, fill);
      sha512_process (ctx);
      input += fill;
      ilen -= fill;
      left = 0;
      fill = SHA512_BLOCK_SIZE;
    }

  memcpy (((unsigned char*)ctx->wbuf) + left, input, ilen);
}

void
sha512_finish (sha512_context *ctx, unsigned char output[64])
{
  uint32_t last = (ctx->total[0] & SHA512_MASK);

  ctx->wbuf[last >> 3] = __builtin_bswap64 (ctx->wbuf[last >> 3]);
  ctx->wbuf[last >> 3] &= 0xffffffffffffff80LL << (8 * (~last & 7));
  ctx->wbuf[last >> 3] |= 0x0000000000000080LL << (8 * (~last & 7));
  ctx->wbuf[last >> 3] = __builtin_bswap64 (ctx->wbuf[last >> 3]);

  if (last > SHA512_BLOCK_SIZE - 17)
    {
      if (last < 120)
        ctx->wbuf[15] = 0;
      sha512_process (ctx);
      last = 0;
    }
  else
    last = (last >> 3) + 1;

  while (last < 14)
    ctx->wbuf[last++] = 0;

  ctx->wbuf[14] = __builtin_bswap64 ((ctx->total[0] >> 61) | (ctx->total[1] << 3));
  ctx->wbuf[15] = __builtin_bswap64 (ctx->total[0] << 3);
  sha512_process (ctx);

  memcpy_output_bswap64 (output, ctx->state);
  memset (ctx, 0, sizeof (sha512_context));
}

/* Taken from section 5.3.5 of [1].  */
static const uint64_t initial_state[8] = {
0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

void
sha512_start (sha512_context *ctx)
{
  ctx->total[0] = ctx->total[1] = 0;
  memcpy (ctx->state, initial_state, 8 * sizeof(uint64_t));
}

void
sha512 (const unsigned char *input, unsigned int ilen,
        unsigned char output[64])
{
  sha512_context ctx;

  sha512_start (&ctx);
  sha512_update (&ctx, input, ilen);
  sha512_finish (&ctx, output);
}
