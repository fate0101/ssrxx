/*
 * encrypt.c - Manage the global encryptor
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */
#include "encrypt.h"
#include "encrypt_common.h"


#ifdef USE_CRYPTO_MBEDTLS

#define SS_CIPHERS_MBEDTLS_MAP(V)                               \
    V(ss_cipher_none,               "none"                  )   \
    V(ss_cipher_table,              "table"                 )   \
    V(ss_cipher_rc4,                "ARC4-128"              )   \
    V(ss_cipher_rc4_md5_6,          "ARC4-128"              )   \
    V(ss_cipher_rc4_md5,            "ARC4-128"              )   \
    V(ss_cipher_aes_128_cfb,        "AES-128-CFB128"        )   \
    V(ss_cipher_aes_192_cfb,        "AES-192-CFB128"        )   \
    V(ss_cipher_aes_256_cfb,        "AES-256-CFB128"        )   \
    V(ss_cipher_aes_128_ctr,        "AES-128-CTR"           )   \
    V(ss_cipher_aes_192_ctr,        "AES-192-CTR"           )   \
    V(ss_cipher_aes_256_ctr,        "AES-256-CTR"           )   \
    V(ss_cipher_bf_cfb,             "BLOWFISH-CFB64"        )   \
    V(ss_cipher_camellia_128_cfb,   "CAMELLIA-128-CFB128"   )   \
    V(ss_cipher_camellia_192_cfb,   "CAMELLIA-192-CFB128"   )   \
    V(ss_cipher_camellia_256_cfb,   "CAMELLIA-256-CFB128"   )   \
    V(ss_cipher_cast5_cfb,          CIPHER_UNSUPPORTED      )   \
    V(ss_cipher_des_cfb,            CIPHER_UNSUPPORTED      )   \
    V(ss_cipher_idea_cfb,           CIPHER_UNSUPPORTED      )   \
    V(ss_cipher_rc2_cfb,            CIPHER_UNSUPPORTED      )   \
    V(ss_cipher_seed_cfb,           CIPHER_UNSUPPORTED      )   \
    V(ss_cipher_salsa20,            "salsa20"               )   \
    V(ss_cipher_chacha20,           "chacha20"              )   \
    V(ss_cipher_chacha20ietf,       "chacha20-ietf"         )   \

static const char *
ss_mbedtls_cipher_name_by_type(enum ss_cipher_type index)
{
#define SS_CIPHER_MBEDTLS_GEN(name, text) case (name): return (text);
	switch (index) {
		SS_CIPHERS_MBEDTLS_MAP(SS_CIPHER_MBEDTLS_GEN)
	default:;  // Silence ss_cipher_max -Wswitch warning.
	}
#undef SS_CIPHER_MBEDTLS_GEN
	return NULL; // "Invalid index";
}

#endif


unsigned char *
enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
	return MD5(d, n, md);
#elif defined(USE_CRYPTO_MBEDTLS)
	static unsigned char m[16];
	if (md == NULL) {
		md = m;
	}
	mbedtls_md5_ret(d, n, md);
	return md;
#endif
}

static int
random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a)
{
	uint8_t x = *((uint8_t *)_x);
	uint8_t y = *((uint8_t *)_y);
	return (int)(a % (x + i) - a % (y + i));
}

void
merge(uint8_t *left, int llength, uint8_t *right,
	int rlength, uint32_t salt, uint64_t key)
{
	uint8_t *ltmp = (uint8_t *)malloc((size_t)llength * sizeof(uint8_t));
	uint8_t *rtmp = (uint8_t *)malloc((size_t)rlength * sizeof(uint8_t));

	uint8_t *ll = ltmp;
	uint8_t *rr = rtmp;

	uint8_t *result = left;

	memcpy(ltmp, left, (size_t)llength * sizeof(uint8_t));
	memcpy(rtmp, right, (size_t)rlength * sizeof(uint8_t));

	while (llength > 0 && rlength > 0) {
		if (random_compare(ll, rr, salt, key) <= 0) {
			*result = *ll;
			++ll;
			--llength;
		}
		else {
			*result = *rr;
			++rr;
			--rlength;
		}
		++result;
	}

	if (llength > 0) {
		while (llength > 0) {
			*result = *ll;
			++result;
			++ll;
			--llength;
		}
	}
	else {
		while (rlength > 0) {
			*result = *rr;
			++result;
			++rr;
			--rlength;
		}
	}

	safe_free(ltmp);
	safe_free(rtmp);
}

void
merge_sort(uint8_t array[], int length, uint32_t salt, uint64_t key)
{
	uint8_t middle;
	uint8_t *left, *right;
	int llength;

	if (length <= 1) {
		return;
	}

	middle = (uint8_t)(length / 2);

	llength = length - middle;

	left = array;
	right = array + llength;

	merge_sort(left, llength, salt, key);
	merge_sort(right, middle, salt, key);
	merge(left, llength, right, middle, salt, key);
}

const digest_type_t *
get_digest_type(const char *digest)
{
	if (digest == NULL) {
		return NULL;
	}

#if defined(USE_CRYPTO_OPENSSL)
	return EVP_get_digestbyname(digest);
#elif defined(USE_CRYPTO_MBEDTLS)
	return mbedtls_md_info_from_string(digest);
#endif
}

int
cipher_key_size(const struct cipher_wrapper *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
	if (cipher->core == NULL) {
		return (int)cipher->key_len;
	}
	else {
		return EVP_CIPHER_key_length(cipher->core);
	}
#elif defined(USE_CRYPTO_MBEDTLS)
	/*
	* Semi-API changes (technically public, morally private)
	* Renamed a few headers to include _internal in the name. Those headers are
	* not supposed to be included by users.
	* Changed md_info_t into an opaque structure (use md_get_xxx() accessors).
	* Changed pk_info_t into an opaque structure.
	* Changed cipher_base_t into an opaque structure.
	*/
	if (cipher == NULL) {
		return 0;
	}
	/* From Version 1.2.7 released 2013-04-13 Default Blowfish keysize is now 128-bits */
	return cipher->core->key_bitlen / 8;
#endif
}

int
bytes_to_key(const struct cipher_wrapper *cipher, const digest_type_t *md,
	const uint8_t *pass, uint8_t *key)
{
	size_t datal;
	mbedtls_md_context_t c;
	unsigned char md_buf[MAX_MD_SIZE];
	int nkey;
	int addmd;
	unsigned int i, j, mds;

	datal = strlen((const char *)pass);
	nkey = 16;
	if (cipher != NULL) {
		nkey = cipher_key_size(cipher);
	}
	mds = mbedtls_md_get_size(md);
	memset(&c, 0, sizeof(mbedtls_md_context_t));

	if (pass == NULL)
		return nkey;
	if (mbedtls_md_setup(&c, md, 1))
		return 0;

	for (j = 0, addmd = 0; j < (unsigned int)nkey; addmd++) {
		mbedtls_md_starts(&c);
		if (addmd) {
			mbedtls_md_update(&c, md_buf, mds);
		}
		mbedtls_md_update(&c, pass, datal);
		mbedtls_md_finish(&c, &(md_buf[0]));

		for (i = 0; i < mds; i++, j++) {
			if (j >= (unsigned int)nkey) {
				break;
			}
			key[j] = md_buf[i];
		}
	}

	mbedtls_md_free(&c);
	return nkey;
}


const cipher_core_t *
get_cipher_of_type(enum ss_cipher_type method)
{
	const char *cipherName;
	if (method >= ss_cipher_salsa20) {
		return NULL;
	}

	if (method == ss_cipher_rc4_md5 || method == ss_cipher_rc4_md5_6) {
		method = ss_cipher_rc4;
	}

	cipherName = ss_cipher_name_of_type(method);
	if (cipherName == NULL) {
		return NULL;
	}
#if defined(USE_CRYPTO_OPENSSL)
	return EVP_get_cipherbyname(cipherName);
#elif defined(USE_CRYPTO_MBEDTLS)
	cipherName = ss_mbedtls_cipher_name_by_type(method);
	if (strcmp(cipherName, CIPHER_UNSUPPORTED) == 0) {
		return NULL;
	}
	return mbedtls_cipher_info_from_string(cipherName);
#endif
}

int
cipher_iv_size(const struct cipher_wrapper *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
	if (cipher->core == NULL) {
		return (int)cipher->iv_len;
	}
	else {
		return EVP_CIPHER_iv_length(cipher->core);
	}
#elif defined(USE_CRYPTO_MBEDTLS)
	if (cipher == NULL) {
		return 0;
	}
	return cipher->core->iv_size;
#endif
}