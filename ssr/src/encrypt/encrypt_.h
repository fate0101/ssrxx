#ifndef encrypt__h
#define encrypt__h

#include <encrypt.h>
#include <encrypt_common.h>
#include <ssr_buffer.hpp>

// #include <ssr_cipher.hpp>
// #include <ssr_obfs.hpp>

namespace ssr{

size_t ss_aes_128_cbc_encrypt(size_t length, const uint8_t *plain_text, uint8_t *out_data, const uint8_t key[16]);
size_t ss_aes_128_cbc_decrypt(size_t length, const uint8_t *cipher_text, uint8_t *out_data, const uint8_t key[16]);

void rand_bytes(uint8_t *output, size_t len);
int rand_integer(void);

void bytes_to_key_with_size(const uint8_t *pass, size_t len, uint8_t *md, size_t md_size);


size_t
ss_sha1_hmac_with_key(uint8_t auth[SHA1_BYTES], SSRBuffer& msg, SSRBuffer& key);

}  // ssr

#endif // encrypt__h