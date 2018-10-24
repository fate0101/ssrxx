#ifndef base_tunnel_hpp
#define base_tunnel_hpp

// system
#include <memory>

// common
#include <ssr_common.h>

// uvw
#include <uvw.hpp>

// server
#include <noncopyable.hpp>


namespace ssr {

template<class TR, class TC, class T>
class BaseTunnel: public noncopyable, public std::enable_shared_from_this<TR> {

public:
	using SSRTHIS = std::enable_shared_from_this<TR>;
	explicit BaseTunnel(std::weak_ptr<T> server):server_(server) {

#ifdef ALL_LOG
		LOG(INFO) << "BaseTunnel Construction";
#endif

	};
	virtual ~BaseTunnel() {

#ifdef ALL_LOG
		LOG(INFO) << "BaseTunnel Deconstruction";
#endif

	};

	virtual void init() = 0;
	virtual void tunnelConnected(std::shared_ptr<uvw::TcpHandle>& ) = 0;
	virtual void tunnelRecved(const uvw::DataEvent &, uvw::TcpHandle&) = 0;
	virtual void tunnelWrited(uvw::TcpHandle&) = 0;

	std::weak_ptr<T> Server() {
		return server_;
	}

	void closeTunnel() {
		auto llsrv = Server().lock();
		if (llsrv == nullptr) return;
		llsrv->closeTunnel(SSRTHIS::shared_from_this());
	}

protected:
	auto createConn(std::shared_ptr<uvw::TcpHandle> handle, std::shared_ptr<uvw::TimerHandle> timer) {
		return std::make_shared<TC>(handle, timer, std::weak_ptr<TR>(SSRTHIS::shared_from_this()));
	}

	std::weak_ptr<T> server_;
};


}  // ssr

#endif  // base_tunnel_h