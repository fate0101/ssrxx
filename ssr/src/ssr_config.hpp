#ifndef ssr_config_hpp
#define ssr_config_hpp

// system and common
#include <string>
#include <ssr_common.h>


namespace ssr {

	struct Config {

		std::string listen_host = "0.0.0.0";
		unsigned short listen_port = 8080;  // if zero , random
		std::string    remote_host;
		unsigned short remote_port;
		std::string    password;
		std::string    method;
		std::string    protocol;
		std::string    protocol_param;
		std::string    obfs;
		std::string    obfs_param;
		bool           udp;
		unsigned int   idle_timeout = 3000; /* connection idle timeout in ms. */
		std::string    remarks;
		~Config() {
#ifdef ALL_LOG
			LOG(INFO) << "config Deconstruction";
#endif
		}
	};


}  // ssr

#endif  // ssr_config_hpp