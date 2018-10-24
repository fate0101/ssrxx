#ifndef ssr_obfs_h
#define ssr_obfs_h

// plugin
#include <ssr_config.hpp>
#include <plugin/obfs/ssr_obfs_base.hpp>


namespace ssr {

	class OBFsFactory {

	public:
		friend class ServerCipher;
		static std::shared_ptr<BaseOBF> createOBFContext(std::shared_ptr<Config>, OBFTYPE, std::shared_ptr<ServerCipher>, void*);
	};


}  // ssr

#endif // ssr_obfs_h