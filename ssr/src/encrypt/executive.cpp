#include <encrypt/executive.h>
#include <encrypt/encrypt_.h>

#include <socks5_tunnel.hpp>


namespace ssr {

	extern int ss_encrypt(std::shared_ptr<SSRBuffer>& plain_buffer, std::shared_ptr<TunnelCipher> tunnel_cipher, struct enc_ctx *ctx, size_t capacity);
	extern int ss_decrypt(std::shared_ptr<SSRBuffer>& cipher_buffer, std::shared_ptr<TunnelCipher> tunnel_cipher, struct enc_ctx *ctx, size_t capacity);

std::shared_ptr<SSRBuffer> initial_package_create(const s5_ctx *parser) {
	auto buffer = std::make_shared<SSRBuffer>(SSR_BUFF_SIZE);
	assert(buffer != nullptr);

	uint8_t *iter = (uint8_t*)buffer->get();
	uint8_t len;
	iter[0] = (uint8_t)parser->atyp;
	iter++;

	switch (parser->atyp) {
	case s5_atyp_ipv4:  // IPv4
		memcpy(iter, parser->daddr, sizeof(struct in_addr));
		iter += sizeof(struct in_addr);
		break;
	case s5_atyp_ipv6:  // IPv6
		memcpy(iter, parser->daddr, sizeof(struct in6_addr));
		iter += sizeof(struct in6_addr);
		break;
	case s5_atyp_host:
		len = (uint8_t)strlen((char *)parser->daddr);
		iter[0] = len;
		iter++;
		memcpy(iter, parser->daddr, len);
		iter += len;
		break;
	default:
		assert(0);
		break;
	}
	*((unsigned short *)iter) = htons(parser->dport);
	iter += sizeof(unsigned short);

	buffer->setlen(iter - (uint8_t*)buffer->get());

	return buffer;
}

// insert shadowsocks header
enum ssr_error tunnel_cipher_client_encrypt(std::shared_ptr<SSRBuffer>& buffer, std::shared_ptr<TunnelCipher>& tunnel_cipher) {
	int err = ssr_ok;
	assert(buffer->size() >= SSR_BUFF_SIZE);

	if (tunnel_cipher->protecol_ != nullptr) {
		tunnel_cipher->protecol_->client_pre_encrypt(buffer);
	}

	err = ss_encrypt(buffer, tunnel_cipher, tunnel_cipher->e_ctx_, SSR_BUFF_SIZE);
	if (err != 0) {
		return ssr_error_invalid_password;
	}

	if (tunnel_cipher->obfs_ != nullptr) {
		tunnel_cipher->obfs_->client_encode(buffer);
	}
	
	return ssr_ok;
}

enum ssr_error tunnel_cipher_client_decrypt(std::shared_ptr<SSRBuffer>& buffer, std::shared_ptr<TunnelCipher>& tunnel_cipher) {
	// assert(buffer->size() <= SSR_BUFF_SIZE);
	
	if (tunnel_cipher->obfs_ != nullptr) {

		tunnel_cipher->obfs_->client_decode(buffer);
		if (buffer == nullptr) return ssr_error_client_decode;
	}
	if (buffer->len() > 0) {
		int err = ss_decrypt(buffer, tunnel_cipher, tunnel_cipher->d_ctx_, SSR_BUFF_SIZE);
		if (err != 0) {
			return ssr_error_invalid_password;
		}
	}
	
	if (tunnel_cipher->protecol_ != nullptr) {
		ssize_t len = tunnel_cipher->protecol_->client_post_decrypt(buffer);
		if (buffer == nullptr) return ssr_error_client_post_decrypt;
	}

	return ssr_ok;
}

}  // ssr
