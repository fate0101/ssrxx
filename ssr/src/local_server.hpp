#ifndef local_server_hpp
#define local_server_hpp

// server
#include <base_server.hpp>
#include <ssr_server_cipher.hpp>


namespace ssr {
    
	class Socks5Tunnel;
	class ServerCipher;

class LocalServer: public BaseServer<LocalServer, Socks5Tunnel> {

public:
	explicit LocalServer() {
	};
	virtual ~LocalServer() {};

	virtual void setConfig(std::shared_ptr<Config> config) {
		auto new_server_cipher = std::make_shared<ServerCipher>(config);
		assert(new_server_cipher != nullptr);
		
		new_server_cipher->init();
		std::swap(config_, config);
		std::swap(server_cipher_, new_server_cipher);
	}

	std::shared_ptr<ServerCipher> getServerCipher() const {
		return server_cipher_;
	}

	std::shared_ptr<ServerCipher>& getCipher() {
		return server_cipher_;
	}

private:
	std::shared_ptr<ServerCipher> server_cipher_;
};


}  // ssr

#endif  // local_server_hpp
