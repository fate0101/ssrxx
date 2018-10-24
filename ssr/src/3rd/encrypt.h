/*
 * encrypt.h - Define the enryptor's interface
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

#ifndef _ENCRYPT_H
#define _ENCRYPT_H


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <cipher/ssr_cipher_names.h>
#include <cache.h>

#define SODIUM_BLOCK_SIZE   64

#define ADDRTYPE_MASK 0xEF

#define MD5_BYTES 16U
#define SHA1_BYTES 20U

#undef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#undef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))


#define MAX_KEY_LENGTH 64

//struct cipher_env_t {
//	uint8_t *enc_table;
//	uint8_t *dec_table;
//	uint8_t enc_key[MAX_KEY_LENGTH];
//	int enc_key_len;
//	int enc_iv_len;
//	enum ss_cipher_type enc_method;
//	struct cache *iv_cache;
//};


////////
// c
#include <stdint.h>
#include <ctype.h>
#define USE_CRYPTO_MBEDTLS

#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#include <mbedtls/aes.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif

#include <sodium.h>

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

typedef mbedtls_cipher_info_t cipher_core_t;
typedef mbedtls_cipher_context_t cipher_core_ctx_t;
typedef mbedtls_md_info_t digest_type_t;

struct cipher_ctx_t {
	cipher_core_ctx_t *core_ctx;
	uint8_t iv[MAX_IV_LENGTH];
};

struct enc_ctx {
	uint8_t init;
	uint64_t counter;
	struct cipher_ctx_t cipher_ctx;
};


struct cipher_wrapper {
	const cipher_core_t *core;
	size_t iv_len;
	size_t key_len;
};

/////////////////////////////////////////////////////////////////////////
// export

EXTERN_C_START

unsigned char *
enc_md5(const unsigned char *d, size_t n, unsigned char *md);

void
merge(uint8_t *left, int llength, uint8_t *right,
	int rlength, uint32_t salt, uint64_t key);

void
merge_sort(uint8_t array[], int length, uint32_t salt, uint64_t key);

const digest_type_t *
get_digest_type(const char *digest);

int
bytes_to_key(const struct cipher_wrapper *cipher, const digest_type_t *md,
	const uint8_t *pass, uint8_t *key);

const cipher_core_t *
get_cipher_of_type(enum ss_cipher_type method);

int
cipher_iv_size(const struct cipher_wrapper *cipher);

// Íâ²¿×ª»»
// ssr_cipher_names.h
int ss_cipher_key_size(enum ss_cipher_type index);
int ss_cipher_iv_size(enum ss_cipher_type index);
const char * ss_cipher_name_of_type(enum ss_cipher_type index);
enum ss_cipher_type ss_cipher_type_of_name(const char *name);
const char * ssr_obfs_name_of_type(enum ssr_obfs index);
enum ssr_obfs ssr_obfs_type_of_name(const char *name);
const char * ssr_protocol_name_of_type(enum ssr_protocol index);
enum ssr_protocol ssr_protocol_type_of_name(const char *name);

// cache.h
int cache_create(struct cache **dst, size_t capacity,
void(*free_cb)(void *key, void *element));
int cache_delete(struct cache *cache, int keep_data);
int cache_clear(struct cache *cache, ev_tstamp age);
int cache_lookup(struct cache *cache, char *key, size_t key_len, void *result);
int cache_insert(struct cache *cache, char *key, size_t key_len, void *data);
int cache_remove(struct cache *cache, char *key, size_t key_len);
int cache_key_exist(struct cache *cache, char *key, size_t key_len);


EXTERN_C_END


#endif // _ENCRYPT_H
