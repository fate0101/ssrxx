#ifndef ssr_obfs_base_hpp
#define ssr_obfs_base_hpp

// server
#include <ssr_buffer.hpp>


namespace ssr {

	enum OBFTYPE {
		NONE,
		PROTOCOL_T,
		OBFS_T
	};

class BaseOBF {

public:
	friend class ServerCipher;
	BaseOBF(std::shared_ptr<ServerCipher> server_cipher): server_cipher_(server_cipher){};
	virtual ~BaseOBF() {};

	virtual size_t client_pre_encrypt(std::shared_ptr<SSRBuffer>&)   = 0;
	virtual size_t client_post_decrypt(std::shared_ptr<SSRBuffer>&) = 0;

	virtual size_t client_encode(std::shared_ptr<SSRBuffer>&) = 0;
	virtual size_t client_decode(std::shared_ptr<SSRBuffer>&) = 0;

	// 
	virtual void* getShared(size_t flag) = 0;

protected:
	std::shared_ptr<ServerCipher> server_cipher_;
};


}  // ssr

#endif // ssr_obfs_base_hpp