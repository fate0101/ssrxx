#ifndef ssr_tunnel_cipher_hpp
#define ssr_tunnel_cipher_hpp

// system
#include <memory>
#include <string>

// entrypt
#include <encrypt/encrypt_.h>

// server
#include <ssr_server_cipher.hpp>
#include <ssr_obfs.h>


namespace ssr {

class TunnelCipher : std::enable_shared_from_this<TunnelCipher> {

public:
	TunnelCipher(std::shared_ptr<ServerCipher> server_cipher, size_t tcp_mss):server_cipher_(server_cipher) {
		tunnel_cipher_create(tcp_mss);
	}

	~TunnelCipher() {
		if (e_ctx_ != NULL) enc_ctx_release_instance(e_ctx_);
		if (d_ctx_ != NULL) enc_ctx_release_instance(d_ctx_);
	}

private:
	void tunnel_cipher_create(size_t tcp_mss) {

		// init tunnel cipher
		if (server_cipher_->enc_method_ > ss_cipher_table) {
			e_ctx_ = enc_ctx_new_instance(true);
			d_ctx_ = enc_ctx_new_instance(false);
		}

		// init tunnel obfs

		// e_ctx_->cipher_ctx.iv use for encrypt
		protecol_ = OBFsFactory::createOBFContext(server_cipher_->config_, PROTOCOL_T, server_cipher_, e_ctx_->cipher_ctx.iv);
		obfs_ = OBFsFactory::createOBFContext(server_cipher_->config_, OBFS_T, server_cipher_, e_ctx_->cipher_ctx.iv);
	}

	struct enc_ctx * enc_ctx_new_instance(bool encrypt) {
		struct enc_ctx *ctx = (struct enc_ctx *)calloc(1, sizeof(struct enc_ctx));
		sodium_memzero(ctx, sizeof(struct enc_ctx));
		cipher_context_init(&ctx->cipher_ctx, encrypt);

		if (encrypt) {
			rand_bytes(ctx->cipher_ctx.iv, server_cipher_->enc_iv_len_);
		}
		return ctx;
	}

	void cipher_context_init(struct cipher_ctx_t *ctx, bool encrypt) {
		const cipher_core_t *cipher;
		const char *cipherName;
		cipher_core_ctx_t *core_ctx;
		enum ss_cipher_type method = server_cipher_->enc_method_;

		if (method >= ss_cipher_salsa20) {
			//        enc_iv_len = ss_cipher_iv_size(method);
			return;
		}

		cipherName = ss_cipher_name_of_type(method);
		if (cipherName == NULL) {
			return;
		}

		cipher = get_cipher_of_type(method);

		if (cipher == NULL) {
#ifdef HAVE_LOG
			LOG(ERROR) << "Cipher %s not found in mbed TLS library" << cipherName;
			LOG(ERROR) << "Cannot initialize mbed TLS cipher";
#endif
		}
		core_ctx = (cipher_core_ctx_t *)calloc(1, sizeof(cipher_core_ctx_t));
		mbedtls_cipher_init(core_ctx);
		if (mbedtls_cipher_setup(core_ctx, cipher) != 0) {
#ifdef HAVE_LOG
			LOG(ERROR) << "Cannot initialize mbed TLS cipher context";
#endif
		}
		ctx->core_ctx = core_ctx;
	}

	void enc_ctx_release_instance(struct enc_ctx *ctx) {
		if (ctx == NULL) return;

		cipher_context_release(&ctx->cipher_ctx);
		safe_free(ctx);
	}

	void cipher_context_release(struct cipher_ctx_t *ctx) {
		if (server_cipher_->enc_method_ >= ss_cipher_salsa20) return;
		
		mbedtls_cipher_free(ctx->core_ctx);
		safe_free(ctx->core_ctx);
	}

public:
	std::shared_ptr<ServerCipher> server_cipher_;

    // use for d/entrypt
	std::shared_ptr<BaseOBF> protecol_;
	std::shared_ptr<BaseOBF> obfs_;

	struct enc_ctx *e_ctx_;
	struct enc_ctx *d_ctx_;
};


}  // ssr

#endif  // ssr_tunnel_cipher_hpp