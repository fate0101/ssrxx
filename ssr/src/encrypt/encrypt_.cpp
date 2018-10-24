#include <encrypt/encrypt_.h>
#include <ssr_tunnel_cipher.hpp>

// #include "ssrbuffer.h"

namespace ssr{
//size_t
//ss_md5_hmac_with_key(uint8_t auth[MD5_BYTES], const struct buffer_t *msg, const struct buffer_t *key)
//{
//	uint8_t hash[MD5_BYTES];
//#if defined(USE_CRYPTO_OPENSSL)
//	HMAC(EVP_md5(), key->buffer, key->len, (unsigned char *)msg->buffer, (size_t)msg->len, (unsigned char *)hash, NULL);
//#elif defined(USE_CRYPTO_MBEDTLS)
//	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), key->buffer, key->len, (uint8_t *)msg->buffer, msg->len, (uint8_t *)hash);
//#endif
//	memcpy(auth, hash, MD5_BYTES);
//
//	return 0;
//}
//
//size_t
//ss_md5_hash_func(uint8_t *auth, const uint8_t *msg, size_t msg_len)
//{
//	uint8_t hash[MD5_BYTES];
//#if defined(USE_CRYPTO_OPENSSL)
//	MD5((unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash);
//#elif defined(USE_CRYPTO_MBEDTLS)
//	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_MD5), (uint8_t *)msg, msg_len, (uint8_t *)hash);
//#endif
//	memcpy(auth, hash, MD5_BYTES);
//
//	return 0;
//}
//
//size_t
//ss_sha1_hmac_with_key(uint8_t auth[SHA1_BYTES], const struct buffer_t *msg, const struct buffer_t *key)
//{
//	uint8_t hash[SHA1_BYTES];
//#if defined(USE_CRYPTO_OPENSSL)
//	HMAC(EVP_sha1(), key->buffer, key->len, msg->buffer, msg->len, hash, NULL);
//#elif defined(USE_CRYPTO_MBEDTLS)
//	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key->buffer, key->len, msg->buffer, msg->len, hash);
//#endif
//	memcpy(auth, hash, SHA1_BYTES);
//
//	return 0;
//}
//
//size_t
//ss_sha1_hash_func(uint8_t *auth, const uint8_t *msg, size_t msg_len)
//{
//	uint8_t hash[SHA1_BYTES];
//#if defined(USE_CRYPTO_OPENSSL)
//	SHA1((unsigned char *)msg, (size_t)msg_len, (unsigned char *)hash);
//#elif defined(USE_CRYPTO_MBEDTLS)
//	mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), (uint8_t *)msg, msg_len, (uint8_t *)hash);
//#endif
//	memcpy(auth, hash, SHA1_BYTES);
//
//	return 0;
//}

size_t ss_aes_128_cbc_encrypt(size_t length, const uint8_t *plain_text, uint8_t *out_data, const uint8_t key[16])
{
	unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(USE_CRYPTO_OPENSSL)
	AES_KEY aes;
	AES_set_encrypt_key((unsigned char*)key, 128, &aes);
	AES_cbc_encrypt((const unsigned char *)plain_text, (unsigned char *)out_data, length, &aes, iv, AES_ENCRYPT);
#elif defined(USE_CRYPTO_MBEDTLS)
	mbedtls_aes_context aes;
	mbedtls_aes_setkey_enc(&aes, (unsigned char *)key, 128);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, (unsigned char *)plain_text, out_data);
#endif
	return 0;
}

size_t ss_aes_128_cbc_decrypt(size_t length, const uint8_t *cipher_text, uint8_t *out_data, const uint8_t key[16])
{
	unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#if defined(USE_CRYPTO_OPENSSL)
	assert(0);
	AES_KEY aes;
	AES_set_encrypt_key((unsigned char*)key, 128, &aes);
	AES_cbc_encrypt((const unsigned char *)cipher_text, (unsigned char *)out_data, length, &aes, iv, AES_DECRYPT);
#elif defined(USE_CRYPTO_MBEDTLS)
	mbedtls_aes_context aes;
	mbedtls_aes_setkey_dec(&aes, key, 128);
	mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iv, cipher_text, out_data);
#endif
	return 0;
}

void rand_bytes(uint8_t *output, size_t len) {
	randombytes_buf(output, (size_t)len);
}

int rand_integer(void) {
	int result = 0;
	rand_bytes((uint8_t *)&result, sizeof(result));
	return abs(result);
}


size_t
ss_sha1_hmac_with_key(uint8_t auth[SHA1_BYTES], SSRBuffer& msg, SSRBuffer& key)
{
	uint8_t hash[SHA1_BYTES];
#if defined(USE_CRYPTO_OPENSSL)
	HMAC(EVP_sha1(), key->buffer, key->len, msg->buffer, msg->len, hash, NULL);
#elif defined(USE_CRYPTO_MBEDTLS)
	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), (const unsigned char*)key.get(), key.len(), (const unsigned char*)msg.get(), msg.len(), hash);
#endif
	memcpy(auth, hash, SHA1_BYTES);

	return 0;
}

void
bytes_to_key_with_size(const uint8_t *pass, size_t len, uint8_t *md, size_t md_size)
{
	int i;
	uint8_t result[128];
	enc_md5((const unsigned char *)pass, len, result);
	memcpy(md, result, 16);
	i = 16;
	for (; i < (int)md_size; i += 16) {
		memcpy(result + 16, pass, len);
		enc_md5(result, 16 + len, result);
		memcpy(md + i, result, 16);
	}
}


void
cipher_context_set_iv(std::shared_ptr<ServerCipher>& server_cipher, struct cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
	mbedtls_operation_t enc)
{
	const unsigned char *true_key;
	cipher_core_ctx_t *core_ctx;

	if (iv == NULL) {
#ifdef HAVE_LOG
		LOG(ERROR) << "cipher_context_set_iv(): IV is null";
#endif
		return;
	}

	if (!enc) {
		memcpy(ctx->iv, iv, iv_len);
	}

	if (server_cipher->enc_method_ >= ss_cipher_salsa20) {
		return;
	}

	if (server_cipher->enc_method_ == ss_cipher_rc4_md5 || server_cipher->enc_method_ == ss_cipher_rc4_md5_6) {
		unsigned char key_iv[32];
		memcpy(key_iv, server_cipher->enc_key_, 16);
		memcpy(key_iv + 16, iv, iv_len);
		true_key = enc_md5(key_iv, 16 + iv_len, NULL);
		iv_len = 0;
	}
	else {
		true_key = server_cipher->enc_key_;
	}
	core_ctx = ctx->core_ctx;
	if (core_ctx == NULL) {
#ifdef HAVE_LOG
		LOG(ERROR) << "cipher_context_set_iv(): Cipher context is null";
#endif
		return;
	}

	if (mbedtls_cipher_setkey(core_ctx, true_key, server_cipher->enc_key_len_ * 8, enc) != 0) {
		mbedtls_cipher_free(core_ctx);
#ifdef HAVE_LOG
		LOG(ERROR) << "Cannot set mbed TLS cipher key";
#endif
	}

	if (mbedtls_cipher_set_iv(core_ctx, iv, iv_len) != 0) {
		mbedtls_cipher_free(core_ctx);
#ifdef HAVE_LOG
		LOG(ERROR) << "Cannot set mbed TLS cipher IV";
#endif
	}
	if (mbedtls_cipher_reset(core_ctx) != 0) {
		mbedtls_cipher_free(core_ctx);
#ifdef HAVE_LOG
		LOG(ERROR) << "Cannot finalize mbed TLS cipher context";
#endif
	}
}

static int
crypto_stream_xor_ic(uint8_t *c, const uint8_t *m, uint64_t mlen,
	const uint8_t *n, uint64_t ic, const uint8_t *k,
	enum ss_cipher_type method)
{
	switch (method) {
	case ss_cipher_salsa20:
		return crypto_stream_salsa20_xor_ic(c, m, mlen, n, ic, k);
	case ss_cipher_chacha20:
		return crypto_stream_chacha20_xor_ic(c, m, mlen, n, ic, k);
	case ss_cipher_chacha20ietf:
		return crypto_stream_chacha20_ietf_xor_ic(c, m, mlen, n, (uint32_t)ic, k);
	default:
		break;
	}
	// always return 0
	return 0;
}

static int
cipher_context_update(struct cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
	const uint8_t *input, size_t ilen)
{
	cipher_core_ctx_t *core_ctx = ctx->core_ctx;
	return !mbedtls_cipher_update(core_ctx, (const uint8_t *)input, ilen,
		(uint8_t *)output, olen);
}

int
ss_encrypt(std::shared_ptr<SSRBuffer>& plain_buffer, std::shared_ptr<TunnelCipher> tunnel_cipher, struct enc_ctx *ctx, size_t capacity) {

	auto server_cipher = tunnel_cipher->server_cipher_;

	if (tunnel_cipher != nullptr) {
		int err = 1;
		size_t iv_len = 0;
		auto cipher_buffer = std::make_shared<SSRBuffer>(MAX(iv_len + plain_buffer->len(), capacity));
		assert(cipher_buffer != nullptr);

		if (!ctx->init) {
			iv_len = (size_t)server_cipher->enc_iv_len_;
		}

		cipher_buffer->setlen(plain_buffer->len());

		if (!ctx->init) {
			cipher_context_set_iv(server_cipher, &ctx->cipher_ctx, ctx->cipher_ctx.iv, iv_len, mbedtls_operation_t::MBEDTLS_ENCRYPT);

			memcpy(cipher_buffer->get(), ctx->cipher_ctx.iv, iv_len);

			ctx->counter = 0;
			ctx->init = 1;
		}

		if (server_cipher->enc_method_ >= ss_cipher_salsa20) {
			size_t padding = (size_t)(ctx->counter % SODIUM_BLOCK_SIZE);

			cipher_buffer->realloc(MAX(iv_len + (padding + cipher_buffer->len()) * 2, capacity));

			if (padding) {

				// 重开空间 往后移 插入
				// 相当于 plain_buffer->insert((const char*)std::unique_ptr<char[10]>{}.get(),10);

				plain_buffer->realloc(MAX(plain_buffer->len() + padding, capacity));

				memmove(plain_buffer->get() + padding, plain_buffer->get(), plain_buffer->len());
				sodium_memzero(plain_buffer->get(), padding);
			}
			crypto_stream_xor_ic((uint8_t *)(cipher_buffer.get() + iv_len),
				(const uint8_t *)plain_buffer->get(),
				((uint64_t)plain_buffer->len() + padding),
				(const uint8_t *)ctx->cipher_ctx.iv,
				ctx->counter / SODIUM_BLOCK_SIZE, server_cipher->enc_key_,
				server_cipher->enc_method_);

			ctx->counter += plain_buffer->len();

			if (padding) {

				memmove(cipher_buffer->get() + iv_len,
					cipher_buffer->get() + iv_len + padding, cipher_buffer->len());
			}
		}
		else {
			auto clen = cipher_buffer->len();

			err =
				cipher_context_update(&ctx->cipher_ctx,
				(uint8_t *)(cipher_buffer->get() + iv_len),
					&clen, (const uint8_t *)plain_buffer->get(), plain_buffer->len());


			if (!err) {
				return -1;
			}

			cipher_buffer->setlen(clen);
		}

		plain_buffer->realloc(MAX(iv_len + cipher_buffer->len(), capacity));
		memcpy(plain_buffer->get(), cipher_buffer->get(), iv_len + cipher_buffer->len());
		plain_buffer->setlen(iv_len + cipher_buffer->len());


		return 0;
	}
	else {
		if (server_cipher->enc_method_ == ss_cipher_table) {
			uint8_t *begin = (uint8_t*)plain_buffer->get();
			uint8_t *ptr = (uint8_t*)plain_buffer->get();
			while (ptr < begin + plain_buffer->len()) {
				*ptr = server_cipher->enc_table_.get()[(uint8_t)*ptr];
				ptr++;
			}
		}
		return 0;
	}
}

int
ss_decrypt(std::shared_ptr<SSRBuffer>& cipher_buffer, std::shared_ptr<TunnelCipher> tunnel_cipher, struct enc_ctx *ctx, size_t capacity){

	auto server_cipher = tunnel_cipher->server_cipher_;
	if (ctx != NULL) {
		size_t iv_len = 0;
		int err = 1;

		auto plain_buffer = std::make_shared<SSRBuffer>(MAX(iv_len + cipher_buffer->len(), capacity));
		assert(plain_buffer != nullptr);

		plain_buffer->setlen(cipher_buffer->len());

		if (!ctx->init) {
			uint8_t iv[MAX_IV_LENGTH];
			iv_len = (size_t)server_cipher->enc_iv_len_;

			plain_buffer->setlen(plain_buffer->len() - iv_len);

			memcpy(iv, cipher_buffer->get(), iv_len);

			cipher_context_set_iv(server_cipher, &ctx->cipher_ctx, iv, iv_len, mbedtls_operation_t::MBEDTLS_DECRYPT);
			ctx->counter = 0;
			ctx->init = 1;

			if (server_cipher->enc_method_ > ss_cipher_rc4) {
				if (cache_key_exist(server_cipher->iv_cache_, (char *)iv, iv_len)) {
					return -1;
				}
				else {
					cache_insert(server_cipher->iv_cache_, (char *)iv, iv_len, NULL);
				}
			}
		}

		if (server_cipher->enc_method_ >= ss_cipher_salsa20) {
			size_t padding = (size_t)(ctx->counter % SODIUM_BLOCK_SIZE);

			plain_buffer->realloc(MAX((plain_buffer->len() + padding) * 2, capacity));

			if (padding) {

				cipher_buffer->realloc(MAX(cipher_buffer->len() + padding, capacity));

				memmove(cipher_buffer->get() + iv_len + padding, cipher_buffer->get() + iv_len,
					cipher_buffer->len() - iv_len);
				sodium_memzero(cipher_buffer->get() + iv_len, padding);
			}
			crypto_stream_xor_ic((uint8_t *)plain_buffer->get(),
				(const uint8_t *)(cipher_buffer->get() + iv_len),
				((uint64_t)cipher_buffer->len() - iv_len + padding),
				(const uint8_t *)ctx->cipher_ctx.iv,
				ctx->counter / SODIUM_BLOCK_SIZE, server_cipher->enc_key_,
				server_cipher->enc_method_);

			ctx->counter += cipher_buffer->len() - iv_len;
			if (padding) {
				memmove(plain_buffer->get(), plain_buffer->get() + padding, plain_buffer->len());
			}
		}
		else {
			auto plen = plain_buffer->len();
			err = cipher_context_update(&ctx->cipher_ctx, (uint8_t *)plain_buffer->get(), &plen,
				(const uint8_t *)(cipher_buffer->get() + iv_len),
				cipher_buffer->len() - iv_len);

			plain_buffer->setlen(plen);
		}

		if (!err) {
			return -1;
		}

		cipher_buffer->realloc(MAX(plain_buffer->len(), capacity));

		memcpy(cipher_buffer->get(), plain_buffer->get(), plain_buffer->len());
		cipher_buffer->setlen(plain_buffer->len());


		return 0;
	}
	else {
		if (server_cipher->enc_method_ == ss_cipher_table) {
			uint8_t *begin = (uint8_t *)cipher_buffer->get();
			uint8_t *ptr = (uint8_t *)cipher_buffer->get();
			while (ptr < begin + cipher_buffer->len()) {
				*ptr = server_cipher->dec_table_.get()[(uint8_t)*ptr];
				ptr++;
			}
		}
		return 0;
	}
}

} // ssr