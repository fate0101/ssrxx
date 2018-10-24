#ifndef executive_h
#define executive_h
#include <ssr_buffer.hpp>
#include <3rd/s5.h>
#include <ssr_tunnel_cipher.hpp>

#define SSR_ERR_MAP(V)                                                         \
  V( 0, ssr_ok,                 "All is OK.")                                  \
  V(-1, ssr_error_client_decode,      "client decode error.")                  \
  V(-2, ssr_error_invalid_password,   "invalid password or cipher.")           \
  V(-3, ssr_error_client_post_decrypt,"client post decrypt error.")            \

typedef enum ssr_error {
#define SSR_ERR_GEN(code, name, _) name = code,
	SSR_ERR_MAP(SSR_ERR_GEN)
#undef SSR_ERR_GEN
	ssr_max_errors,
} ssr_error;


#ifndef SSR_BUFF_SIZE_
#define SSR_BUFF_SIZE_
const size_t SSR_BUFF_SIZE = 2048;
#else
EXTERN_C const size_t SSR_BUFF_SIZE;
#endif



namespace ssr {
	std::shared_ptr<SSRBuffer> initial_package_create(const s5_ctx *parser);
	enum ssr_error tunnel_cipher_client_encrypt(std::shared_ptr<SSRBuffer>& buffer, std::shared_ptr<TunnelCipher>& tunnel_cipher);
	enum ssr_error tunnel_cipher_client_decrypt(std::shared_ptr<SSRBuffer>& buffer, std::shared_ptr<TunnelCipher>& tunnel_cipher);
};

#endif // executive_h