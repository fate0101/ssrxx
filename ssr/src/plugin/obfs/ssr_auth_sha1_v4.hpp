#ifndef ssr_auth_sha1_v4_hpp
#define ssr_auth_sha1_v4_hpp

// system
#include <WinSock2.h>

// encrypt
#include <encrypt/executive.h>

// server
#include <ssr_server_cipher.hpp>

// obfs
#include "ssr_obfs_base.hpp"
#include "ssr_auth_common.h"


namespace ssr {

class AUTH_SHA1_V4 : public BaseOBF {

public:
	AUTH_SHA1_V4(std::shared_ptr<ServerCipher> server_cipher, void* context)
		: BaseOBF(server_cipher) {

		rand_bytes(shared_data_.local_client_id, 8);
		rand_bytes((uint8_t*)&shared_data_.connection_id, 4);
		shared_data_.connection_id &= 0xFFFFFF;
		
		// iv_ for ss_sha1_hmac
		iv_ = (uint8_t*)context;

		// server_ciper not need initialization
		if(server_cipher != nullptr)
			local_data_init();
	};

	virtual ~AUTH_SHA1_V4() {};

	virtual size_t client_pre_encrypt(std::shared_ptr<SSRBuffer>& plainbuff) {
		assert(server_cipher_->server_protocol_ != nullptr);

		char *plaindata = plainbuff->get();
		size_t datalength = plainbuff->len();


		char * out_buffer = (char*)malloc((size_t)(datalength * 2 + (SSR_BUFF_SIZE * 2)));
		char * buffer = out_buffer;
		char * data = plaindata;
		size_t len = datalength;
		size_t pack_len;
		if (len > 0 && local_.has_sent_header == 0) {
			size_t head_size = get_s5_head_size((const uint8_t *)plaindata, datalength, 30);
			if (head_size > datalength) {
				head_size = datalength;
			}
			pack_len = auth_sha1_v4_pack_auth_data(data, head_size, buffer);
			buffer += pack_len;
			data += head_size;
			len -= head_size;
			local_.has_sent_header = 1;
		}
		while (len > auth_simple_pack_unit_size) {
			pack_len = auth_sha1_v4_pack_data(data, auth_simple_pack_unit_size, buffer);
			buffer += pack_len;
			data += auth_simple_pack_unit_size;
			len -= auth_simple_pack_unit_size;
		}
		if (len > 0) {
			pack_len = auth_sha1_v4_pack_data(data, len, buffer);
			buffer += pack_len;
		}
		len = (int)(buffer - out_buffer);
		if ((int)plainbuff->size() < len) {

			plainbuff->realloc((size_t)(len * 2));
		}
		// len >= 0
		memmove(plainbuff->get(), out_buffer, len);
		plainbuff->setlen(len);

		free(out_buffer);
		return len;

	}

	virtual size_t client_post_decrypt(std::shared_ptr<SSRBuffer>& plainbuff) {
		assert(server_cipher_->server_protocol_ != nullptr);
		int len;
		char error;
		char * buffer;

		char *plaindata = plainbuff->get();
		size_t datalength = plainbuff->len();

		uint8_t * recv_buffer = (uint8_t *)local_.recv_buffer->get();
		if (local_.recv_buffer->len() + datalength > 16384) {
			return -1;
		}
		memmove(recv_buffer + local_.recv_buffer->len(), plaindata, datalength);
		local_.recv_buffer->setlen(local_.recv_buffer->len() + datalength);


		auto out_buffer = std::make_shared<SSRBuffer>(local_.recv_buffer->len());

		buffer = out_buffer->get();

		error = 0;
		while (local_.recv_buffer->len() > 4) {
			size_t length;
			size_t pos;
			size_t data_size;
			uint32_t crc_val = crc32_imp((unsigned char*)recv_buffer, 2);
			if ((((uint32_t)recv_buffer[3] << 8) | recv_buffer[2]) != (crc_val & 0xffff)) {
				local_.recv_buffer->setlen(0);
				error = 1;
				break;
			}
			length = (size_t)ntohs(*(uint16_t *)(recv_buffer + 0)); // ((int)recv_buffer[0] << 8) | recv_buffer[1];
			if (length >= 8192 || length < 7) {
				local_.recv_buffer->setlen(0);
				error = 1;
				break;
			}
			if (length > local_.recv_buffer->len()) {
				break;
			}
			if (checkadler32((unsigned char*)recv_buffer, length) == false) {
				local_.recv_buffer->setlen(0);
				error = 1;
				break;
			}
			pos = recv_buffer[4];
			if (pos < 255) {
				pos += 4;
			}
			else {
				pos = (((int)recv_buffer[5] << 8) | recv_buffer[6]) + 4;
			}
			data_size = length - pos - 4;
			memmove(buffer, recv_buffer + pos, data_size);
			buffer += data_size;

			// length >= 0
			local_.recv_buffer->setlen(local_.recv_buffer->len() - length);
			memmove(recv_buffer, recv_buffer + length, local_.recv_buffer->len());
		}
		if (error == 0) {
			len = (int)(buffer - out_buffer->get());
			if ((int)plainbuff->size() < len) {
				plainbuff->realloc(len * 2);
			}
			memmove(plainbuff->get(), out_buffer->get(), len);

			// len >= 0
			plainbuff->setlen(len);
		}
		else {
			len = -1;
		}
		return (size_t)len;
	}

	virtual size_t client_encode(std::shared_ptr<SSRBuffer>& buffer) {
		return 0;
	}

	virtual size_t client_decode(std::shared_ptr<SSRBuffer>& buffer) {
		return 0;
	}

private:
	void local_data_init() {
		local_.has_sent_header = 0;
		local_.recv_buffer = std::make_shared<SSRBuffer>(16384);
		local_.recv_id = 1;
		local_.pack_id = 1;
		local_.user_key = std::make_shared<SSRBuffer>(SSR_BUFF_SIZE);
		// local->hmac = 0;
		// local->hash = 0;
		local_.hash_len = 0;
		local_.unit_len = 2000; // 8100
		local_.has_recv_header = false;
		{
			uint16_t extra_wait_size;
			rand_bytes((uint8_t *)&extra_wait_size, sizeof(extra_wait_size));
			local_.extra_wait_size = (size_t)(extra_wait_size % 1024);
		}
		local_.max_time_dif = 60 * 60 * 24;
		local_.salt = "auth_sha1_v4";
	}

	void* getShared(size_t flag) {
		return &shared_data_;
	}

	size_t	auth_sha1_v4_pack_auth_data(char *data, size_t datalength, char *outdata) {

		auth_simple_global_data *global = (auth_simple_global_data*)server_cipher_->server_protocol_->getShared(0);


		uint8_t hash[SHA1_BYTES];
		time_t t;
		unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
		size_t data_offset = (size_t)rand_len + 4 + 2;
		size_t out_size = data_offset + datalength + 12 + OBFS_HMAC_SHA1_LEN;
		const char* salt = "auth_sha1_v4";
		size_t salt_len = (size_t)strlen(salt);
		unsigned char *crc_salt = (unsigned char*)malloc((size_t)salt_len + server_cipher_->enc_key_len_ + 2);
		crc_salt[0] = (unsigned char)(outdata[0] = (char)(out_size >> 8));
		crc_salt[1] = (unsigned char)(outdata[1] = (char)out_size);

		memcpy(crc_salt + 2, salt, salt_len);
		memcpy(crc_salt + salt_len + 2, server_cipher_->enc_key_, server_cipher_->enc_key_len_);
		fillcrc32to(crc_salt, (unsigned int)((size_t)salt_len + server_cipher_->enc_key_len_ + 2), (unsigned char *)outdata + 2);
		free(crc_salt);
		if (rand_len < 128) {
			outdata[6] = (char)rand_len;
		}
		else {
			outdata[6] = (char)0xFF;
			outdata[7] = (char)(rand_len >> 8);
			outdata[8] = (char)rand_len;
		}
		++global->connection_id;
		if (global->connection_id > 0xFF000000) {
			rand_bytes(global->local_client_id, 8);
			rand_bytes((uint8_t*)&global->connection_id, 4);
			global->connection_id &= 0xFFFFFF;
		}
		t = time(NULL);
		memintcopy_lt(outdata + data_offset, (uint32_t)t);
		memmove(outdata + data_offset + 4, global->local_client_id, 4);
		memintcopy_lt(outdata + data_offset + 8, global->connection_id);
		memmove(outdata + data_offset + 12, data, datalength);
		ss_sha1_hmac(hash, (uint8_t *)outdata, out_size - OBFS_HMAC_SHA1_LEN, iv_, server_cipher_->enc_iv_len_, server_cipher_->enc_key_, server_cipher_->enc_key_len_);
		memcpy(outdata + out_size - OBFS_HMAC_SHA1_LEN, hash, OBFS_HMAC_SHA1_LEN);
		return out_size;
	}

	size_t	auth_sha1_v4_pack_data(char *data, size_t datalength, char *outdata) {
		uint32_t crc_val;
		unsigned int rand_len = (datalength > 1300 ? 0 : datalength > 400 ? (xorshift128plus() & 0x7F) : (xorshift128plus() & 0x3FF)) + 1;
		size_t out_size = (size_t)rand_len + datalength + 8;
		outdata[0] = (char)(out_size >> 8);
		outdata[1] = (char)out_size;
		crc_val = crc32_imp((unsigned char*)outdata, 2);
		outdata[2] = (char)crc_val;
		outdata[3] = (char)(crc_val >> 8);
		if (rand_len < 128) {
			outdata[4] = (char)rand_len;
		}
		else {
			outdata[4] = (char)0xFF;
			outdata[5] = (char)(rand_len >> 8);
			outdata[6] = (char)rand_len;
		}
		memmove(outdata + rand_len + 4, data, datalength);
		filladler32((unsigned char *)outdata, (unsigned int)out_size);
		return out_size;
	}

private:
	auth_simple_global_data shared_data_;
	auth_simple_local_data  local_;

	// context
	uint8_t* iv_;
};


}  // ssr

#endif // ssr_auth_sha1_v4