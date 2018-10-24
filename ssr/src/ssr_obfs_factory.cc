// plugin
#include <ssr_obfs.h>
#include <encrypt/encrypt_.h>
#include <plugin/util/crc32.h>
#include <plugin/util/obfsutil.h>
#include <plugin/obfs/ssr_auth_sha1_v4.hpp>


namespace ssr {

std::shared_ptr<BaseOBF> OBFsFactory::createOBFContext(std::shared_ptr<Config> config, OBFTYPE ot, \
	std::shared_ptr<ServerCipher> server_cipher, void* context) {

	enum ssr_protocol protocol_type = ssr_protocol_origin;
	enum ssr_obfs obfs_type = ssr_obfs_plain;
	std::string  plugin_name;

	if (ot == OBFS_T)
		plugin_name = config->obfs;
	else if(ot == PROTOCOL_T)
		plugin_name = config->protocol;
	else
		return nullptr;

	if (plugin_name.empty()) {
		return nullptr;
	}
	if (ot == PROTOCOL_T) {
		protocol_type = ssr_protocol_type_of_name(plugin_name.c_str());
		if (ssr_protocol_origin == protocol_type) {
			// origin
			return nullptr;
		}
	}	
	else {
		obfs_type = ssr_obfs_type_of_name(plugin_name.c_str());
		if (ssr_obfs_plain == obfs_type) {
			// plain
			return nullptr;
		}
	}
	

	init_crc32_table();
	init_shift128plus();

	std::shared_ptr<BaseOBF> obf = nullptr;

	if (ot == OBFS_T) {
		switch (obfs_type) {
		case ssr_obfs_http_simple:
		default:
			break;
		}
	
	}
	else{
		switch (protocol_type) {

		// auth_sha1_v4
		case ssr_protocol_auth_sha1_v4: {
			obf = std::make_shared<AUTH_SHA1_V4>(server_cipher, context);
		}break;

		default:
			break;
		}
	}

	/// if (ssr_obfs_http_simple == obfs_type) {
	/// 	// http_simple
	/// 	return http_simple_new_obfs();
	/// }
	/// else if (ssr_obfs_http_post == obfs_type) {
	/// 	// http_post
	/// 	return http_post_new_obfs();
	/// }
	/// else if (ssr_obfs_http_mix == obfs_type) {
	/// 	// http_mix
	/// 	return http_mix_new_obfs();
	/// }
	/// else if (ssr_obfs_tls_1_2_ticket_auth == obfs_type) {
	/// 	// tls1.2_ticket_auth
	/// 	struct obfs_t * plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	tls12_ticket_auth_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else if (ssr_obfs_tls_1_2_ticket_fastauth == obfs_type) {
	/// 	// tls1.2_ticket_fastauth
	/// 	struct obfs_t * plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	tls12_ticket_fastauth_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else if (ssr_protocol_verify_simple == protocol_type) {
	/// 	// verify_simple
	/// 	struct obfs_t * plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	verify_simple_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else if (ssr_protocol_auth_simple == protocol_type) {
	/// 	// auth_simple
	/// 	struct obfs_t * plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	auth_simple_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else if (ssr_protocol_auth_sha1 == protocol_type) {
	/// 	// auth_sha1
	/// 	struct obfs_t * plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	auth_sha1_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else if (ssr_protocol_auth_sha1_v2 == protocol_type) {
	/// 	// auth_sha1_v2
	/// 	struct obfs_t *plugin = (struct obfs_t*)calloc(1, sizeof(struct obfs_t));
	/// 	auth_sha1_v2_new_obfs(plugin);
	/// 	return plugin;
	/// }
	/// else 

	/// else if (ssr_protocol_auth_aes128_md5 == protocol_type) {
	/// 	// auth_aes128_md5
	/// 	return auth_aes128_md5_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_aes128_sha1 == protocol_type) {
	/// 	// auth_aes128_sha1
	/// 	return auth_aes128_sha1_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_a == protocol_type) {
	/// 	// auth_chain_a
	/// 	return auth_chain_a_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_b == protocol_type) {
	/// 	// auth_chain_b
	/// 	return auth_chain_b_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_c == protocol_type) {
	/// 	// auth_chain_c
	/// 	return auth_chain_c_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_d == protocol_type) {
	/// 	// auth_chain_d
	/// 	return auth_chain_d_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_e == protocol_type) {
	/// 	// auth_chain_e
	/// 	return auth_chain_e_new_obfs();
	/// }
	/// else if (ssr_protocol_auth_chain_f == protocol_type) {
	/// 	// auth_chain_f
	/// 	return auth_chain_f_new_obfs();
	/// }


	return obf;
}


}  // ssr
