/*
 * openpgp-do.c -- OpenPGP card Data Objects (DO) handling
 *
 * Copyright (C) 2010 Free Software Initiative of Japan
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

#include <stdlib.h>

#include "config.h"
#include "ch.h"
#include "gnuk.h"
#include "openpgp.h"

#include "polarssl/config.h"
#include "polarssl/aes.h"
#include "polarssl/sha1.h"

static uint32_t digital_signature_counter;

static const uint8_t *
gpg_write_digital_signature_counter (const uint8_t *p, uint32_t dsc)
{
  uint16_t hw0, hw1;

  if ((dsc >> 10) == 0)
    { /* no upper bits */
      hw1 = NR_COUNTER_DS_LSB | ((dsc & 0x0300) >> 8) | ((dsc & 0x00ff) << 8);
      flash_put_data_internal (p, hw1);
      return p+2;
    }
  else
    {
      hw0 = NR_COUNTER_DS | ((dsc & 0xfc0000) >> 18) | ((dsc & 0x03fc00) >> 2);
      hw1 = NR_COUNTER_DS_LSB;
      flash_put_data_internal (p, hw0);
      flash_put_data_internal (p+2, hw1);
      return p+4;
    }
}

void
gpg_increment_digital_signature_counter (void)
{
  uint16_t hw0, hw1;
  uint32_t dsc = (digital_signature_counter + 1) & 0x00ffffff;

  if ((dsc & 0x03ff) == 0)
    { /* carry occurs from l10 to h14 */
      hw0 = NR_COUNTER_DS | ((dsc & 0xfc0000) >> 18) | ((dsc & 0x03fc00) >> 2);
      hw1 = NR_COUNTER_DS_LSB;	/* zero */
      flash_put_data (hw0);
      flash_put_data (hw1);
    }
  else
    {
      hw1 = NR_COUNTER_DS_LSB | ((dsc & 0x0300) >> 8) | ((dsc & 0x00ff) << 8);
      flash_put_data (hw1);
    }

  digital_signature_counter = dsc;
}

#define PASSWORD_ERRORS_MAX 3	/* >= errors, it will be locked */
const uint8_t *pw_err_counter_p[3];

static int
gpg_get_pw_err_counter (uint8_t which)
{
  return flash_cnt123_get_value (pw_err_counter_p[which]);
}

int
gpg_passwd_locked (uint8_t which)
{
  if (gpg_get_pw_err_counter (which) >= PASSWORD_ERRORS_MAX)
    return 1;
  else
    return 0;
}

void
gpg_reset_pw_err_counter (uint8_t which)
{
  flash_cnt123_clear (&pw_err_counter_p[which]);
  if (pw_err_counter_p[which] != NULL)
    GPG_MEMORY_FAILURE ();
}

void
gpg_increment_pw_err_counter (uint8_t which)
{
  flash_cnt123_increment (which, &pw_err_counter_p[which]);
}


uint16_t data_objects_number_of_bytes;

/*
 * Compile time vars:
 *   AID, Historical Bytes (template), Extended Capabilities,
 *   and Algorithm Attributes
 */

/* AID */
const uint8_t openpgpcard_aid[17] __attribute__ ((aligned (1))) = {
  16,
  0xd2, 0x76, 0x00, 0x01, 0x24, 0x01,
  0x02, 0x00,			/* Version 2.0 */
  MANUFACTURER_IN_AID,
  SERIAL_NUMBER_IN_AID,
  0x00, 0x00
};

/* Historical Bytes (template) */
static const uint8_t historical_bytes[] __attribute__ ((aligned (1))) = {
  10,
  0x00,
  0x31, 0x80,			/* Full DF name */
  0x73,
  0x80, 0x01, 0x40,		/* Full DF name */
				/* 1-byte */
				/* No command chaining */
				/* Extended Lc and Le */
  0x00, 0x90, 0x00		/* Status info (no life cycle management) */
};

/* Extended Capabilities */
static const uint8_t extended_capabilities[] __attribute__ ((aligned (1))) = {
  10,
  0x30,				/*
				 * No SM, No get challenge,
				 * Key import supported,
				 * PW status byte can be put,
				 * No private_use_DO,
				 * No algo change allowed
				 */
  0,		  /* Secure Messaging Algorithm: N/A (TDES=0, AES=1) */
  0x00, 0x00,	  /* Max get challenge */
  0x00, 0x00,	  /* max. length of cardholder certificate */
  (MAX_CMD_APDU_SIZE>>8), (MAX_CMD_APDU_SIZE&0xff), /* Max. length of command data */
  (MAX_RES_APDU_SIZE>>8), (MAX_RES_APDU_SIZE&0xff), /* Max. length of response data */
};

/* Algorithm Attributes */
static const uint8_t algorithm_attr[] __attribute__ ((aligned (1))) = {
  6,
  0x01, /* RSA */
  0x08, 0x00,	      /* Length modulus (in bit): 2048 */
  0x00, 0x20,	      /* Length exponent (in bit): 32  */
  0x00		      /* 0: p&q , 3: CRT with N (not yet supported) */
};

#define PW_LEN_MAX 127
/*
 * Representation of PW1_LIFETIME:
 *    0: PW1_LIEFTIME_P == NULL : PW1 is valid for single PSO:CDS command
 *    1: PW1_LIEFTIME_P != NULL : PW1 is valid for several PSO:CDS commands
 *
 * The address in the variable PW1_LIEFTIME_P is used when filling zero
 * in flash memory
 */
static const uint8_t *pw1_lifetime_p;
int
gpg_get_pw1_lifetime (void)
{
  if (pw1_lifetime_p == NULL)
    return 0;
  else
    return 1;
}

#define SIZE_FINGER_PRINT 20
#define SIZE_KEYGEN_TIME 4	/* RFC4880 */

enum do_type {
  DO_FIXED,
  DO_VAR,
  DO_CMP_READ,
  DO_PROC_READ,
  DO_PROC_WRITE,
  DO_PROC_READWRITE,
};

struct do_table_entry {
  uint16_t tag;
  enum do_type do_type;
  uint8_t ac_read;
  uint8_t ac_write;
  const void *obj;
};

static uint8_t *res_p;

static void copy_do_1 (uint16_t tag, const uint8_t *do_data, int with_tag);
static const struct do_table_entry *get_do_entry (uint16_t tag);

#define GPG_DO_AID		0x004f
#define GPG_DO_NAME		0x005b
#define GPG_DO_LOGIN_DATA	0x005e
#define GPG_DO_CH_DATA		0x0065
#define GPG_DO_APP_DATA		0x006e
/* XXX: 0x0073 ??? */
#define GPG_DO_SS_TEMP		0x007a
#define GPG_DO_DS_COUNT		0x0093
#define GPG_DO_EXTCAP		0x00c0
#define GPG_DO_ALG_SIG		0x00c1
#define GPG_DO_ALG_DEC		0x00c2
#define GPG_DO_ALG_AUT		0x00c3
#define GPG_DO_PW_STATUS	0x00c4
#define GPG_DO_FP_ALL		0x00c5
#define GPG_DO_CAFP_ALL		0x00c6
#define GPG_DO_FP_SIG		0x00c7
#define GPG_DO_FP_DEC		0x00c8
#define GPG_DO_FP_AUT		0x00c9
#define GPG_DO_CAFP_1		0x00ca
#define GPG_DO_CAFP_2		0x00cb
#define GPG_DO_CAFP_3		0x00cc
#define GPG_DO_KGTIME_ALL	0x00cd
#define GPG_DO_KGTIME_SIG	0x00ce
#define GPG_DO_KGTIME_DEC	0x00cf
#define GPG_DO_KGTIME_AUT	0x00d0
#define GPG_DO_RESETTING_CODE	0x00d3
#define GPG_DO_KEY_IMPORT	0x3fff
#define GPG_DO_LANGUAGE		0x5f2d
#define GPG_DO_SEX		0x5f35
#define GPG_DO_URL		0x5f50
#define GPG_DO_HIST_BYTES	0x5f52
#define GPG_DO_CH_CERTIFICATE	0x7f21

static const uint8_t *do_ptr[NR_DO__LAST__];

static uint8_t
do_tag_to_nr (uint16_t tag)
{
  switch (tag)
    {
    case GPG_DO_SEX:
      return NR_DO_SEX;
    case GPG_DO_FP_SIG:
      return NR_DO_FP_SIG;
    case GPG_DO_FP_DEC:
      return NR_DO_FP_DEC;
    case GPG_DO_FP_AUT:
      return NR_DO_FP_AUT;
    case GPG_DO_CAFP_1:
      return NR_DO_CAFP_1;
    case GPG_DO_CAFP_2:
      return NR_DO_CAFP_2;
    case GPG_DO_CAFP_3:
      return NR_DO_CAFP_3;
    case GPG_DO_KGTIME_SIG:
      return NR_DO_KGTIME_SIG;
    case GPG_DO_KGTIME_DEC:
      return NR_DO_KGTIME_DEC;
    case GPG_DO_KGTIME_AUT:
      return NR_DO_KGTIME_AUT;
    case GPG_DO_LOGIN_DATA:
      return NR_DO_LOGIN_DATA;
    case GPG_DO_URL:
      return NR_DO_URL;
    case GPG_DO_NAME:
      return NR_DO_NAME;
    case GPG_DO_LANGUAGE:
      return NR_DO_LANGUAGE;
    default:
      fatal ();
    }
}

static void
copy_tag (uint16_t tag)
{
  if (tag < 0x0100)
    *res_p++ = (tag & 0xff);
  else
    {
      *res_p++ = (tag >> 8);
      *res_p++ = (tag & 0xff);
    }
}

static int
do_hist_bytes (uint16_t tag, int with_tag)
{
  /* XXX: For now, no life cycle management, just return template as is. */
  /* XXX: Supporing TERMINATE DF / ACTIVATE FILE, we need to fix here */
  copy_do_1 (tag, historical_bytes, with_tag);
  return 1;
}

#define SIZE_FP 20
#define SIZE_KGTIME 4

static int
do_fp_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_FP*3;
    }

  data = gpg_do_read_simple (NR_DO_FP_SIG);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_FP_DEC);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_FP_AUT);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;
  return 1;
}

static int
do_cafp_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_FP*3;
    }

  data = gpg_do_read_simple (NR_DO_CAFP_1);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_CAFP_2);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;

  data = gpg_do_read_simple (NR_DO_CAFP_2);
  if (data)
    memcpy (res_p, data, SIZE_FP);
  else
    memset (res_p, 0, SIZE_FP);
  res_p += SIZE_FP;
  return 1;
}

static int
do_kgtime_all (uint16_t tag, int with_tag)
{
  const uint8_t *data;

  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = SIZE_KGTIME*3;
    }

  data = gpg_do_read_simple (NR_DO_KGTIME_SIG);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;

  data = gpg_do_read_simple (NR_DO_KGTIME_DEC);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;

  data = gpg_do_read_simple (NR_DO_KGTIME_AUT);
  if (data)
    memcpy (res_p, data, SIZE_KGTIME);
  else
    memset (res_p, 0, SIZE_KGTIME);
  res_p += SIZE_KGTIME;
  return 1;
}

static int
do_ds_count (uint16_t tag, int with_tag)
{
  if (with_tag)
    {
      copy_tag (tag);
      *res_p++ = 3;
    }

  *res_p++ = (digital_signature_counter >> 16) & 0xff;
  *res_p++ = (digital_signature_counter >> 8) & 0xff;
  *res_p++ = digital_signature_counter & 0xff;
  return 1;
}

static int
rw_pw_status (uint16_t tag, int with_tag,
	      const uint8_t *data, int len, int is_write)
{
  if (is_write)
    {
      (void)len;		/* Should be SIZE_PW_STATUS_BYTES */

      /* Only the first byte of DATA is checked */
      if (data[0] == 0)
	{
	  flash_bool_clear (&pw1_lifetime_p);
	  if (pw1_lifetime_p == NULL)
	    return 1;
	  else
	    return 0;
	}
      else
	{
	  pw1_lifetime_p = flash_bool_write (NR_BOOL_PW1_LIFETIME);
	  if (pw1_lifetime_p != NULL)
	    return 1;
	  else
	    return 0;
	}
    }
  else
    {
      if (with_tag)
	{
	  copy_tag (tag);
	  *res_p++ = SIZE_PW_STATUS_BYTES;
	}

      *res_p++ = gpg_get_pw1_lifetime ();
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PW_LEN_MAX;
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_get_pw_err_counter (PW_ERR_PW1);
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_get_pw_err_counter (PW_ERR_RC);
      *res_p++ = PASSWORD_ERRORS_MAX - gpg_get_pw_err_counter (PW_ERR_PW3);
      return 1;
    }
}

static int
proc_resetting_code (const uint8_t *data, int len)
{
  const uint8_t *old_ks = keystring_md_pw3;
  uint8_t new_ks0[KEYSTRING_MD_SIZE+1];
  uint8_t *new_ks = &new_ks0[1];
  const uint8_t *newpw;
  int newpw_len;
  int r;

  DEBUG_INFO ("Resetting Code!\r\n");

  newpw_len = len;
  newpw = data;
  sha1 (newpw, newpw_len, new_ks);
  new_ks0[0] = newpw_len;
  r = gpg_change_keystring (BY_ADMIN, old_ks, BY_RESETCODE, new_ks);
  if (r < -2)
    {
      DEBUG_INFO ("memory error.\r\n");
      return 0;
    }
  else if (r < 0)
    {
      DEBUG_INFO ("security error.\r\n");
      return 0;
    }
  else if (r == 0)
    {
      DEBUG_INFO ("done (no prvkey).\r\n");
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, new_ks0, KEYSTRING_SIZE_RC);
    }
  else
    {
      DEBUG_INFO ("done.\r\n");
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, new_ks0, 1);
    }

  gpg_reset_pw_err_counter (PW_ERR_RC);
  return 1;
}

static void
encrypt (const uint8_t *key_str, uint8_t *data, int len)
{
  aes_context aes;
  uint8_t iv[16];
  int iv_offset;

  DEBUG_INFO ("ENC\r\n");
  DEBUG_BINARY (data, len);

  aes_setkey_enc (&aes, key_str, 128);
  memset (iv, 0, 16);
  iv_offset = 0;
  aes_crypt_cfb128 (&aes, AES_ENCRYPT, len, &iv_offset, iv, data, data);
}

struct key_data kd;

static void
decrypt (const uint8_t *key_str, uint8_t *data, int len)
{
  aes_context aes;
  uint8_t iv[16];
  int iv_offset;

  aes_setkey_enc (&aes, key_str, 128);
  memset (iv, 0, 16);
  iv_offset = 0;
  aes_crypt_cfb128 (&aes, AES_DECRYPT, len, &iv_offset, iv, data, data);

  DEBUG_INFO ("DEC\r\n");
  DEBUG_BINARY (data, len);
}

static uint8_t
get_do_ptr_nr_for_kk (enum kind_of_key kk)
{
  switch (kk)
    {
    case GPG_KEY_FOR_SIGNING:
      return NR_DO_PRVKEY_SIG;
    case GPG_KEY_FOR_DECRYPTION:
      return NR_DO_PRVKEY_DEC;
    case GPG_KEY_FOR_AUTHENTICATION:
      return NR_DO_PRVKEY_AUT;
    }
  return NR_DO_PRVKEY_SIG;
}

/*
 * Return  1 on success,
 *         0 if none,
 *        -1 on error,
 */
int
gpg_do_load_prvkey (enum kind_of_key kk, int who, const uint8_t *keystring)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  const uint8_t *do_data = do_ptr[nr - NR_DO__FIRST__];
  uint8_t *key_addr;
  uint8_t dek[DATA_ENCRYPTION_KEY_SIZE];

  if (do_data == NULL)
    return 0;

  key_addr = *(uint8_t **)&(do_data)[1];
  memcpy (kd.data, key_addr, KEY_CONTENT_LEN);
  memcpy (((uint8_t *)&kd.check), do_data+5, ADDITIONAL_DATA_SIZE);
  memcpy (dek, do_data+5+16*who, DATA_ENCRYPTION_KEY_SIZE);

  decrypt (keystring, dek, DATA_ENCRYPTION_KEY_SIZE);
  decrypt (dek, (uint8_t *)&kd, sizeof (struct key_data));
  if (memcmp (kd.magic, GNUK_MAGIC, KEY_MAGIC_LEN) != 0)
    {
      DEBUG_INFO ("gpg_do_load_prvkey failed.\r\n");
      return -1;
    }
  /* more sanity check??? */
  return 1;
}

static uint32_t
calc_check32 (const uint8_t *p, int len)
{
  uint32_t check = 0;
  uint32_t *data = (uint32_t *)p;
  int i;

  for (i = 0; i < len/4; i++)
    check += data[i];

  return check;
}

static int8_t num_prv_keys;

int
gpg_do_write_prvkey (enum kind_of_key kk, const uint8_t *key_data, int key_len,
		     const uint8_t *keystring)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  const uint8_t *p;
  int r;
  const uint8_t *modulus;
  struct prvkey_data *pd;
  uint8_t *key_addr;
  const uint8_t *dek;
  const uint8_t *do_data = do_ptr[nr - NR_DO__FIRST__];
  const uint8_t *ks_pw1;
  const uint8_t *ks_rc;

#if 0
  assert (key_len == KEY_CONTENT_LEN);
#endif

  DEBUG_INFO ("Key import\r\n");
  DEBUG_SHORT (key_len);

  pd = (struct prvkey_data *)malloc (sizeof (struct prvkey_data));
  if (pd == NULL)
    return -1;

  modulus = modulus_calc (key_data, key_len);
  if (modulus == NULL)
    {
      free (pd);
      return -1;
    }

  DEBUG_INFO ("Getting keystore address...\r\n");
  key_addr = flash_key_alloc ();
  if (key_addr == NULL)
    {
      free (pd);
      modulus_free (modulus);
      return -1;
    }

  DEBUG_INFO ("key_addr: ");
  DEBUG_WORD ((uint32_t)key_addr);

  memcpy (kd.data, key_data, KEY_CONTENT_LEN);
  kd.check = calc_check32 (key_data, KEY_CONTENT_LEN);
  kd.random = get_random ();
  memcpy (kd.magic, GNUK_MAGIC, KEY_MAGIC_LEN);

  if (do_data)			/* We have old prvkey */
    {
      /* Write new prvkey resetting PW1 and RC */
      /* Note: if you have other prvkey(s), it becomes bogus */
      memcpy (pd, do_data+1, sizeof (struct prvkey_data));
      decrypt (keystring_md_pw3, pd->dek_encrypted_3, DATA_ENCRYPTION_KEY_SIZE);
      dek = pd->dek_encrypted_3;
      memcpy (pd->dek_encrypted_1, dek, DATA_ENCRYPTION_KEY_SIZE);
      memset (pd->dek_encrypted_2, 0, DATA_ENCRYPTION_KEY_SIZE);
      gpg_do_write_simple (NR_DO_KEYSTRING_PW1, NULL, 0);
      gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);
      flash_key_release (pd->key_addr);
      flash_do_release (do_data);
      ks_pw1 = NULL;
      ks_rc = NULL;
    }
  else
    {
      dek = random_bytes_get (); /* 16-byte random bytes */
      memcpy (pd->dek_encrypted_1, dek, DATA_ENCRYPTION_KEY_SIZE);
      memcpy (pd->dek_encrypted_2, dek, DATA_ENCRYPTION_KEY_SIZE);
      memcpy (pd->dek_encrypted_3, dek, DATA_ENCRYPTION_KEY_SIZE);
      ks_pw1 = gpg_do_read_simple (NR_DO_KEYSTRING_PW1);
      ks_rc = gpg_do_read_simple (NR_DO_KEYSTRING_RC);
    }

  encrypt (dek, (uint8_t *)&kd, sizeof (struct key_data));

  r = flash_key_write (key_addr, kd.data, modulus);
  modulus_free (modulus);

  if (r < 0)
    {
      if (do_data == NULL)
	random_bytes_free (dek);
      free (pd);
      return r;
    }

  pd->key_addr = key_addr;
  memcpy (pd->crm_encrypted, (uint8_t *)&kd.check, ADDITIONAL_DATA_SIZE);

  ac_reset_pso_cds ();
  if (ks_pw1)
    encrypt (ks_pw1+1, pd->dek_encrypted_1, DATA_ENCRYPTION_KEY_SIZE);
  else
    {
      uint8_t ks123_pw1[KEYSTRING_SIZE_PW1];

      ks123_pw1[0] = strlen (OPENPGP_CARD_INITIAL_PW1);
      sha1 ((uint8_t *)OPENPGP_CARD_INITIAL_PW1, 
	    strlen (OPENPGP_CARD_INITIAL_PW1), ks123_pw1+1);
      encrypt (ks123_pw1+1, pd->dek_encrypted_1, DATA_ENCRYPTION_KEY_SIZE);
    }

  if (ks_rc)
    encrypt (ks_rc+1, pd->dek_encrypted_2, DATA_ENCRYPTION_KEY_SIZE);
  else
    memset (pd->dek_encrypted_2, 0, DATA_ENCRYPTION_KEY_SIZE);

  encrypt (keystring, pd->dek_encrypted_3, DATA_ENCRYPTION_KEY_SIZE);

  p = flash_do_write (nr, (const uint8_t *)pd, sizeof (struct prvkey_data));
  do_ptr[nr - NR_DO__FIRST__] = p;

  if (do_data == NULL)
    random_bytes_free (dek);
  free (pd);
  if (p == NULL)
    return -1;

  if (do_data == NULL
      && ++num_prv_keys == NUM_ALL_PRV_KEYS) /* All keys are registered.  */
    {
      /* Remove contents of keystrings from DO, but length */
      if (ks_pw1)
	{
	  uint8_t ks_pw1_len = ks_pw1[0];
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW1, &ks_pw1_len, 1);
	}

      if (ks_rc)
	{
	  uint8_t ks_rc_len = ks_rc[0];
	  gpg_do_write_simple (NR_DO_KEYSTRING_RC, &ks_rc_len, 1);
	}
    }

  return 0;
}

int
gpg_do_chks_prvkey (enum kind_of_key kk,
		    int who_old, const uint8_t *old_ks,
		    int who_new, const uint8_t *new_ks)
{
  uint8_t nr = get_do_ptr_nr_for_kk (kk);
  const uint8_t *do_data = do_ptr[nr - NR_DO__FIRST__];
  uint8_t dek[DATA_ENCRYPTION_KEY_SIZE];
  struct prvkey_data *pd;
  const uint8_t *p;
  uint8_t *dek_p;

  if (do_data == NULL)
    return 0;			/* No private key */

  pd = (struct prvkey_data *)malloc (sizeof (struct prvkey_data));
  if (pd == NULL)
    return -1;

  memcpy (pd, &(do_data)[1], sizeof (struct prvkey_data));
  dek_p = ((uint8_t *)pd) + 4 + ADDITIONAL_DATA_SIZE + DATA_ENCRYPTION_KEY_SIZE * (who_old - 1);
  memcpy (dek, dek_p, DATA_ENCRYPTION_KEY_SIZE);
  decrypt (old_ks, dek, DATA_ENCRYPTION_KEY_SIZE);
  encrypt (new_ks, dek, DATA_ENCRYPTION_KEY_SIZE);
  dek_p += DATA_ENCRYPTION_KEY_SIZE * (who_new - who_old);
  memcpy (dek_p, dek, DATA_ENCRYPTION_KEY_SIZE);

  p = flash_do_write (nr, (const uint8_t *)pd, sizeof (struct prvkey_data));
  do_ptr[nr - NR_DO__FIRST__] = p;

  flash_do_release (do_data);
  free (pd);
  if (p == NULL)
    return -1;

  return 1;
}

/*
 * 4d, xx, xx:    Extended Header List
 *   b6 00 (SIG) / b8 00 (DEC) / a4 00 (AUT)
 *   7f48, xx: cardholder private key template
 *       91 xx
 *       92 xx
 *       93 xx
 *   5f48, xx: cardholder private key
 */
static int
proc_key_import (const uint8_t *data, int len)
{
  int r;
  enum kind_of_key kk;

  DEBUG_BINARY (data, len);

  if (data[4] == 0xb6)
    kk = GPG_KEY_FOR_SIGNING;
  else if (data[4] == 0xb8)
    kk = GPG_KEY_FOR_DECRYPTION;
  else				/* 0xa4 */
    kk = GPG_KEY_FOR_AUTHENTICATION;

  if (len <= 22)
    {					    /* Deletion of the key */
      uint8_t nr = get_do_ptr_nr_for_kk (kk);
      const uint8_t *do_data = do_ptr[nr - NR_DO__FIRST__];

      /* Delete the key */
      if (do_data)
	{
	  uint8_t *key_addr = *(uint8_t **)&do_data[1];

	  flash_key_release (key_addr);
	  flash_do_release (do_data);
	}
      do_ptr[nr - NR_DO__FIRST__] = NULL;

      if (--num_prv_keys == 0)
	{
	  /* Delete PW1 and RC if any */
	  gpg_do_write_simple (NR_DO_KEYSTRING_PW1, NULL, 0);
	  gpg_do_write_simple (NR_DO_KEYSTRING_RC, NULL, 0);
	}

      return 1;
    }

  /* It should starts with 00 01 00 01 (E) */
  /* Skip E, 4-byte */
  r = gpg_do_write_prvkey (kk, &data[26], len - 26, keystring_md_pw3);
  if (r < 0)
    return 0;
  else
    return 1;
}

static const uint16_t const cmp_ch_data[] = {
  3,
  GPG_DO_NAME,
  GPG_DO_LANGUAGE,
  GPG_DO_SEX,
};

static const uint16_t const cmp_app_data[] = {
  10,
  GPG_DO_AID,
  GPG_DO_HIST_BYTES,
  /* XXX Discretionary data objects 0x0073 ??? */
  GPG_DO_EXTCAP,
  GPG_DO_ALG_SIG, GPG_DO_ALG_DEC, GPG_DO_ALG_AUT,
  GPG_DO_PW_STATUS,
  GPG_DO_FP_ALL, GPG_DO_CAFP_ALL, GPG_DO_KGTIME_ALL
};

static const uint16_t const cmp_ss_temp[] = { 1, GPG_DO_DS_COUNT };

static const struct do_table_entry
gpg_do_table[] = {
  /* Variables: Fixed size */
  { GPG_DO_SEX, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[0] },
  { GPG_DO_FP_SIG, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[1] },
  { GPG_DO_FP_DEC, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[2] },
  { GPG_DO_FP_AUT, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[3] },
  { GPG_DO_CAFP_1, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[4] },
  { GPG_DO_CAFP_2, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[5] },
  { GPG_DO_CAFP_3, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[6] },
  { GPG_DO_KGTIME_SIG, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[7] },
  { GPG_DO_KGTIME_DEC, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[8] },
  { GPG_DO_KGTIME_AUT, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[9] },
  /* Variables: Variable size */
  { GPG_DO_LOGIN_DATA, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[10] },
  { GPG_DO_URL, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[11] },
  { GPG_DO_NAME, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[12] },
  { GPG_DO_LANGUAGE, DO_VAR, AC_ALWAYS, AC_ADMIN_AUTHORIZED, &do_ptr[13] },
  /* Pseudo DO READ: calculated */
  { GPG_DO_HIST_BYTES, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_hist_bytes },
  { GPG_DO_FP_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_fp_all },
  { GPG_DO_CAFP_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_cafp_all },
  { GPG_DO_KGTIME_ALL, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_kgtime_all },
  /* Pseudo DO READ: calculated, not changeable by user */
  { GPG_DO_DS_COUNT, DO_PROC_READ, AC_ALWAYS, AC_NEVER, do_ds_count },
  /* Pseudo DO READ/WRITE: calculated */
  { GPG_DO_PW_STATUS, DO_PROC_READWRITE, AC_ALWAYS, AC_ADMIN_AUTHORIZED,
    rw_pw_status },
  /* Fixed data */
  { GPG_DO_AID, DO_FIXED, AC_ALWAYS, AC_NEVER, openpgpcard_aid },
  { GPG_DO_EXTCAP, DO_FIXED, AC_ALWAYS, AC_NEVER, extended_capabilities },
  { GPG_DO_ALG_SIG, DO_FIXED, AC_ALWAYS, AC_NEVER, algorithm_attr },
  { GPG_DO_ALG_DEC, DO_FIXED, AC_ALWAYS, AC_NEVER, algorithm_attr },
  { GPG_DO_ALG_AUT, DO_FIXED, AC_ALWAYS, AC_NEVER, algorithm_attr },
  /* Compound data: Read access only */
  { GPG_DO_CH_DATA, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_ch_data },
  { GPG_DO_APP_DATA, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_app_data },
  { GPG_DO_SS_TEMP, DO_CMP_READ, AC_ALWAYS, AC_NEVER, cmp_ss_temp },
  /* Simple data: write access only */
  { GPG_DO_RESETTING_CODE, DO_PROC_WRITE, AC_NEVER, AC_ADMIN_AUTHORIZED,
    proc_resetting_code },
  /* Compound data: Write access only */
  { GPG_DO_KEY_IMPORT, DO_PROC_WRITE, AC_NEVER, AC_ADMIN_AUTHORIZED,
    proc_key_import },
  /* Card holder certificate: Not supported yet */
  { GPG_DO_CH_CERTIFICATE, DO_PROC_READWRITE, AC_NEVER, AC_NEVER, NULL },
};

#define NUM_DO_ENTRIES (int)(sizeof (gpg_do_table) / sizeof (struct do_table_entry))

/*
 * Reading data from Flash ROM, initialize DO_PTR, PW_ERR_COUNTERS, etc. 
 */
void
gpg_data_scan (const uint8_t *p_start)
{
  const uint8_t *p;
  int i;
  const uint8_t *dsc_h14_p, *dsc_l10_p;
  int dsc_h14, dsc_l10;

  dsc_h14_p = dsc_l10_p = NULL;
  pw1_lifetime_p = NULL;
  pw_err_counter_p[PW_ERR_PW1] = NULL;
  pw_err_counter_p[PW_ERR_RC] = NULL;
  pw_err_counter_p[PW_ERR_PW3] = NULL;

  /* Traverse DO, counters, etc. in DATA pool */
  p = p_start;
  while (*p != NR_EMPTY)
    {
      uint8_t nr = *p++;
      uint8_t second_byte = *p;

      if (nr == 0x00 && second_byte == 0x00)
	p++;			/* Skip released word */
      else
	{
	  if (nr < 0x80)
	    {
	      /* It's Data Object */
	      do_ptr[nr - NR_DO__FIRST__] = p;
	      p += second_byte + 1; /* second_byte has length */

	      if (((uint32_t)p & 1))
		p++;
	    }
	  else if (nr >= 0x80 && nr <= 0xbf)
	    /* Encoded data of Digital Signature Counter: upper 14-bit */
	    {
	      dsc_h14_p = p - 1;
	      p++;
	    }
	  else if (nr >= 0xc0 && nr <= 0xc3)
	    /* Encoded data of Digital Signature Counter: lower 10-bit */
	    {
	      dsc_l10_p = p - 1;
	      p++;
	    }
	  else
	    switch (nr)
	    {
	    case NR_BOOL_PW1_LIFETIME:
	      pw1_lifetime_p = p - 1;
	      p++;
	      continue;
	    case NR_COUNTER_123:
	      p++;
	      if (second_byte <= PW_ERR_PW3)
		pw_err_counter_p[second_byte] = p;
	      p += 2;
	      break;
	    }
	}
    }

  flash_set_data_pool_last (p);

  num_prv_keys = 0;
  if (do_ptr[NR_DO_PRVKEY_SIG - NR_DO__FIRST__] != NULL)
    num_prv_keys++;
  if (do_ptr[NR_DO_PRVKEY_DEC - NR_DO__FIRST__] != NULL)
    num_prv_keys++;
  if (do_ptr[NR_DO_PRVKEY_AUT - NR_DO__FIRST__] != NULL)
    num_prv_keys++;

  data_objects_number_of_bytes = 0;
  for (i = NR_DO__FIRST__; i < NR_DO__LAST__; i++)
    if (do_ptr[i - NR_DO__FIRST__] != NULL)
      data_objects_number_of_bytes += *do_ptr[i - NR_DO__FIRST__];

  if (dsc_l10_p == NULL)
    dsc_l10 = 0;
  else
    dsc_l10 = ((*dsc_l10_p - 0xc0) << 8) | *(dsc_l10_p + 1);

  if (dsc_h14_p == NULL)
    dsc_h14 = 0;
  else
    {
      dsc_h14 = ((*dsc_h14_p - 0x80) << 8) | *(dsc_h14_p + 1);
      if (dsc_l10_p == NULL)
	DEBUG_INFO ("something wrong in DSC\r\n"); /* weird??? */
      else if (dsc_l10_p < dsc_h14_p)
	/* Possibly, power off during writing dsc_l10 */
	dsc_l10 = 0;
    }

  digital_signature_counter = (dsc_h14 << 10) | dsc_l10;
}

void
gpg_data_copy (const uint8_t *p_start)
{
  const uint8_t *p;
  int i;
  int v;

  p = gpg_write_digital_signature_counter (p_start, digital_signature_counter);

  if (pw1_lifetime_p != NULL)
    {
      flash_bool_write_internal (p, NR_BOOL_PW1_LIFETIME);
      pw1_lifetime_p = p;
      p += 2;
    }

  for (i = 0; i < 3; i++)
    if ((v = flash_cnt123_get_value (pw_err_counter_p[i])) != 0)
      {
	flash_cnt123_write_internal (p, i, v);
	pw_err_counter_p[i] = p + 2;
	p += 4;
      }

  data_objects_number_of_bytes = 0;
  for (i = NR_DO__FIRST__; i < NR_DO__LAST__; i++)
    if (do_ptr[i - NR_DO__FIRST__] != NULL)
      {
	const uint8_t *do_data = do_ptr[i - NR_DO__FIRST__];
	int len = do_data[0];

	flash_do_write_internal (p, i, &do_data[1], len);
	do_ptr[i - NR_DO__FIRST__] = p + 1;
	p += 2 + ((len + 1) & ~1);
	data_objects_number_of_bytes += len;
      }

  flash_set_data_pool_last (p);
}

static const struct do_table_entry *
get_do_entry (uint16_t tag)
{
  int i;

  for (i = 0; i < NUM_DO_ENTRIES; i++)
    if (gpg_do_table[i].tag == tag)
      return &gpg_do_table[i];

  return NULL;
}

static void
copy_do_1 (uint16_t tag, const uint8_t *do_data, int with_tag)
{
  int len;

  if (with_tag)
    {
      copy_tag (tag);

      if (do_data[0] >= 128)
	*res_p++ = 0x81;

      len = do_data[0] + 1;
    }
  else
    {
      len = do_data[0];
      do_data++;
    }

  memcpy (res_p, do_data, len);
  res_p += len;
}

static int
copy_do (const struct do_table_entry *do_p, int with_tag)
{
  if (do_p == NULL)
    return 0;

  if (!ac_check_status (do_p->ac_read))
    return -1;

  switch (do_p->do_type)
    {
    case DO_FIXED:
      {
	const uint8_t *do_data = (const uint8_t *)do_p->obj;
	if (do_data == NULL)
	  return 0;
	else
	  copy_do_1 (do_p->tag, do_data, with_tag);
	break;
      }
    case DO_VAR:
      {
	const uint8_t *do_data = *(const uint8_t **)do_p->obj;
	if (do_data == NULL)
	  return 0;
	else
	  copy_do_1 (do_p->tag, do_data, with_tag);
	break;
      }
    case DO_CMP_READ:
      {
	int i;
	const uint16_t *cmp_data = (const uint16_t *)do_p->obj;
	int num_components = cmp_data[0];
	uint8_t *len_p;

	copy_tag (do_p->tag);
	*res_p++ = 0x81;	/* Assume it's less than 256 */
	len_p = res_p;
	*res_p++ = 0;		/* for now */

	for (i = 0; i < num_components; i++)
	  {
	    uint16_t tag0;
	    const struct do_table_entry *do0_p;

	    tag0 = cmp_data[i+1];
	    do0_p = get_do_entry (tag0);
	    if (copy_do (do0_p, 1) < 0)
	      return -1;
	  }

	*len_p = (res_p - len_p);
	break;
      }
    case DO_PROC_READ:
      {
	int (*do_func)(uint16_t, int) = (int (*)(uint16_t, int))do_p->obj;

	return do_func (do_p->tag, with_tag);
      }
    case DO_PROC_READWRITE:
      {
	int (*rw_func)(uint16_t, int, uint8_t *, int, int)
	  = (int (*)(uint16_t, int, uint8_t *, int, int))do_p->obj;

	return rw_func (do_p->tag, with_tag, NULL, 0, 0);
      }
    case DO_PROC_WRITE:
      return -1;
    }

  return 1;
}

/*
 * Process GET_DATA request on Data Object specified by TAG
 *   Call write_res_adpu to fill data returned
 */
void
gpg_do_get_data (uint16_t tag)
{
  const struct do_table_entry *do_p = get_do_entry (tag);

  res_p = res_APDU;

  DEBUG_INFO ("   ");
  DEBUG_SHORT (tag);

  if (do_p)
    {
      if (copy_do (do_p, 0) < 0)
	/* Overwriting partially written result  */
	GPG_SECURITY_FAILURE ();
      else
	{
	  *res_p++ = 0x90;
	  *res_p++ = 0x00;
	  res_APDU_size = res_p - res_APDU;
	}
    }
  else
    GPG_NO_RECORD();
}

void
gpg_do_put_data (uint16_t tag, const uint8_t *data, int len)
{
  const struct do_table_entry *do_p = get_do_entry (tag);

  DEBUG_INFO ("   ");
  DEBUG_SHORT (tag);

  if (do_p)
    {
      if (!ac_check_status (do_p->ac_write))
	{
	  GPG_SECURITY_FAILURE ();
	  return;
	}

      switch (do_p->do_type)
	{
	case DO_FIXED:
	case DO_CMP_READ:
	case DO_PROC_READ:
	  GPG_SECURITY_FAILURE ();
	  break;
	case DO_VAR:
	  {
	    const uint8_t **do_data_p = (const uint8_t **)do_p->obj;

	    if (*do_data_p)
	      flash_do_release (*do_data_p);

	    if (len == 0)
	      /* make DO empty */
	      *do_data_p = NULL;
	    else if (len > 255)
	      GPG_MEMORY_FAILURE ();
	    else
	      {
		uint8_t nr = do_tag_to_nr (tag);

		*do_data_p = flash_do_write (nr, data, len);
		if (*do_data_p)
		  GPG_SUCCESS ();
		else
		  GPG_MEMORY_FAILURE ();
	      }
	    break;
	  }
	case DO_PROC_READWRITE:
	  {
	    int (*rw_func)(uint16_t, int, const uint8_t *, int, int)
	      = (int (*)(uint16_t, int, const uint8_t *, int, int))do_p->obj;

	    if (rw_func (tag, 0, data, len, 1))
	      GPG_SUCCESS ();
	    else
	      GPG_ERROR ();
	    break;
	  }
	case DO_PROC_WRITE:
	  {
	    int (*proc_func)(const uint8_t *, int)
	      = (int (*)(const uint8_t *, int))do_p->obj;

	    if (proc_func (data, len))
	      GPG_SUCCESS ();
	    else
	      GPG_ERROR ();
	    break;
	  }
	}
    }
  else
    GPG_NO_RECORD();
}

void
gpg_do_public_key (uint8_t kk_byte)
{
  const uint8_t *do_data;
  const uint8_t *key_addr;

  DEBUG_INFO ("Public key\r\n");
  DEBUG_BYTE (kk_byte);

  if (kk_byte == 0xb6)
    do_data = do_ptr[NR_DO_PRVKEY_SIG - NR_DO__FIRST__];
  else if (kk_byte == 0xb8)
    do_data = do_ptr[NR_DO_PRVKEY_DEC - NR_DO__FIRST__];
  else				/* 0xa4 */
    do_data = do_ptr[NR_DO_PRVKEY_AUT - NR_DO__FIRST__];

  if (do_data == NULL)
    {
      DEBUG_INFO ("none.\r\n");
      GPG_NO_RECORD();
      return;
    }

  key_addr = *(const uint8_t **)&do_data[1];

  res_p = res_APDU;

  /* TAG */
  *res_p++ = 0x7f; *res_p++ = 0x49;
  /* LEN = 9+256 */
  *res_p++ = 0x82; *res_p++ = 0x01; *res_p++ = 0x09;

  {
    /*TAG*/          /*LEN = 256 */
    *res_p++ = 0x81; *res_p++ = 0x82; *res_p++ = 0x01; *res_p++ = 0x00;
    /* 256-byte binary (big endian) */
    memcpy (res_p, key_addr + KEY_CONTENT_LEN, KEY_CONTENT_LEN);
    res_p += 256;
  }
  {
    /*TAG*/          /*LEN= 3 */
    *res_p++ = 0x82; *res_p++ = 3;
    /* 3-byte E=0x10001 (big endian) */
    *res_p++ = 0x01; *res_p++ = 0x00; *res_p++ = 0x01;

    /* Success */
    *res_p++ = 0x90; *res_p++ = 0x00;
    res_APDU_size = res_p - res_APDU;
  }

  DEBUG_INFO ("done.\r\n");
  return;
}

const uint8_t *
gpg_do_read_simple (uint8_t nr)
{
  const uint8_t *do_data;

  do_data = do_ptr[nr - NR_DO__FIRST__];
  if (do_data == NULL)
    return NULL;

  return do_data+1;
}

void
gpg_do_write_simple (uint8_t nr, const uint8_t *data, int size)
{
  const uint8_t **do_data_p;

  do_data_p = (const uint8_t **)&do_ptr[nr - NR_DO__FIRST__];
  if (*do_data_p)
    flash_do_release (*do_data_p);

  if (data != NULL)
    {
      *do_data_p = flash_do_write (nr, data, size);
      if (*do_data_p == NULL)
	flash_warning ("DO WRITE ERROR");
    }
  else
    *do_data_p = NULL;
}