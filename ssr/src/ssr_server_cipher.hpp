#ifndef ssr_server_cipher_hpp
#define ssr_server_cipher_hpp

// system
#include <memory>
#include <string>

// common
#include <ssr_config.hpp>
#include <ssr_common.h>

// server
#include <ssr_buffer.hpp>
#include <ssr_obfs.h>

// 3rd
#include <encrypt/encrypt_.h>


namespace ssr {

class ServerCipher : std::enable_shared_from_this<ServerCipher> {

public:
	ServerCipher(std::shared_ptr<Config> config):config_ (config) {

	}

	~ServerCipher() {
		// ensure release
		if (iv_cache_)
			cache_delete(iv_cache_, 0);
	}

	void enc_table_init(){

		uint32_t i;
		uint64_t key = 0;
		uint8_t *digest;

		enc_table_.alloc(256);
		dec_table_.alloc(256);

		auto enc_table = (uint8_t *)enc_table_.get();
		auto dec_table = (uint8_t *)dec_table_.get();



		assert(config_->password.length() > 0 && config_->password.length() < MAX_KEY_LENGTH);

		digest = enc_md5((const uint8_t *)config_->password.c_str(), config_->password.length(), NULL);

		for (i = 0; i < 8; i++) {
			key += OFFSET_ROL(digest, i);
		}
		for (i = 0; i < 256; ++i) {
			enc_table[i] = (uint8_t)i;
		}
		for (i = 1; i < 1024; ++i) {
			merge_sort(enc_table, 256, i, key);
		}
		for (i = 0; i < 256; ++i) {
			// gen decrypt table from encrypt table
			dec_table[enc_table[i]] = (uint8_t)i;
		}

		if (enc_method_ == ss_cipher_table) {
			enc_key_len_ = (int)config_->password.length();
			memcpy(enc_key_, config_->password.c_str(), enc_key_len_);
		}
		else {
			const digest_type_t *md = get_digest_type("MD5");

			enc_key_len_ = bytes_to_key(NULL, md, (const uint8_t *)config_->password.c_str(), enc_key_);

			if (enc_key_len_ == 0) {
#ifdef HAVE_LOG
				LOG(ERROR) << "Cannot generate key and IV";
#endif
			}
		}

		enc_iv_len_ = 0;
	}

	void enc_key_init() {
		struct cipher_wrapper *cipher_w;
		const digest_type_t *md;

		auto method = enc_method_;

		if (method < ss_cipher_none || method >= ss_cipher_max) {
#ifdef HAVE_LOG
			LOG(ERROR) << "enc_key_init(): Illegal method";
#endif
			abort();
		}

		// Initialize cache
		cache_create(&iv_cache_, 256, NULL);

		cipher_w = (struct cipher_wrapper *)calloc(1, sizeof(cipher_wrapper));

		// Initialize sodium for random generator
		if (sodium_init() == -1) {
#ifdef HAVE_LOG
			LOG(ERROR) << "Failed to initialize sodium";
#endif
			abort();
		}

		if (method == ss_cipher_salsa20 || method == ss_cipher_chacha20 || method == ss_cipher_chacha20ietf) {
			// XXX: key_length changed to key_bitlen in mbed TLS 2.0.0

			cipher_core_t cipher_info = { MBEDTLS_CIPHER_NONE };
			cipher_info.base = NULL;
			cipher_info.key_bitlen = (unsigned int)ss_cipher_key_size(method) * 8;
			cipher_info.iv_size = (unsigned int)ss_cipher_iv_size(method);

			cipher_w->core = &cipher_info;
		}
		else {
			cipher_w->core = get_cipher_of_type(method);
		}

		if (cipher_w->core == NULL && cipher_w->key_len == 0) {
#ifdef HAVE_LOG
			LOG(ERROR) << "Cipher " << ss_cipher_name_of_type(method) << " not found in crypto library";
			LOG(ERROR) << "Cannot initialize cipher";
#endif
			abort();
		}

		md = get_digest_type("MD5");
		if (md == NULL) {
#ifdef HAVE_LOG
			LOG(ERROR) << "MD5 Digest not found in crypto library";
#endif
			abort();
		}

		enc_key_len_ = bytes_to_key(cipher_w, md, (const uint8_t *)config_->password.c_str(), enc_key_);

		if (enc_key_len_ == 0) {
#ifdef HAVE_LOG
			LOG(ERROR) << "Cannot generate key and IV";
#endif
			abort();
		}
		if (method == ss_cipher_rc4_md5 || method == ss_cipher_rc4_md5_6) {
			enc_iv_len_ = ss_cipher_iv_size(method);
		}
		else {
			enc_iv_len_ = cipher_iv_size(cipher_w);
		}
		free(cipher_w);
	}

	bool init() {

		enc_method_ = ss_cipher_type_of_name(config_->method.c_str());
		if (enc_method_ <= ss_cipher_table) enc_table_init();
		else enc_key_init();
		
		server_protocol_ = OBFsFactory::createOBFContext(config_, PROTOCOL_T, nullptr, nullptr);
		server_obfs_ = OBFsFactory::createOBFContext(config_, OBFS_T, nullptr, nullptr);

		return true;
	}

	//  d/encrypt table
	SSRBuffer enc_table_;
	SSRBuffer dec_table_;
	uint8_t enc_key_[MAX_KEY_LENGTH];
	int enc_key_len_;
	int enc_iv_len_;
	enum ss_cipher_type enc_method_;
	struct cache        *iv_cache_;

	// config
	std::shared_ptr<Config> config_;

	// obfs obj
	std::shared_ptr<BaseOBF> server_protocol_;
	std::shared_ptr<BaseOBF> server_obfs_;
};


}  // ssr

#endif  // ssr_server_cipher_hpp