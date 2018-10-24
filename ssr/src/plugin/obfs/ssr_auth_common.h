#ifndef ssr_auth_common_h
#define ssr_auth_common_h

// system
#include <memory>

// server
#include <ssr_buffer.hpp>

// define
#define OBFS_HMAC_SHA1_LEN 10


namespace ssr {

static const size_t auth_simple_pack_unit_size = 2000;

typedef struct _auth_simple_global_data {
	uint8_t local_client_id[8];
	uint32_t connection_id;
} auth_simple_global_data;

typedef struct _auth_simple_local_data {
	int has_sent_header;
	std::shared_ptr<SSRBuffer> recv_buffer;
	uint32_t recv_id;
	uint32_t pack_id;
	std::string salt;
	std::shared_ptr <SSRBuffer> user_key;
	char uid[4];
	// hmac_with_key_func hmac;
	// hash_func hash;
	int hash_len;
	size_t last_data_len;
	size_t unit_len;
	bool has_recv_header;
	size_t extra_wait_size;
	int max_time_dif;
	uint32_t client_id;
	uint32_t connection_id;
} auth_simple_local_data;


}  // ssr

#endif  // ssr_auth_common_h