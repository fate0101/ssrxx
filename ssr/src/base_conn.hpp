#ifndef base_conn_h
#define base_conn_h

// system
#include <memory>

// common
#include <ssr_common.h>

// uvw
#include <uvw.hpp>


namespace ssr {

template <class T>
class BaseConn: public noncopyable {

public:
	explicit BaseConn(
		std::shared_ptr<uvw::TcpHandle>   handle,
		std::shared_ptr<uvw::TimerHandle> timer,
		std::weak_ptr<T> tunnel)
		:handle_(handle), timer_(timer), tunnel_(tunnel) {
#ifdef ALL_LOG
		LOG(INFO) << "BaseConn Construction";
#endif
	};

	~BaseConn() {

#ifdef ALL_LOG
		LOG(INFO) << "BaseConn Deconstruction";
#endif
		timer_->close();
	};

	void RunTimeOut() {
		auto tunnel = tunnel_.lock();
		if (tunnel == nullptr) return;

		auto llsrv = tunnel->Server().lock();
		if (llsrv == nullptr) {
			// tunnel->closeTunnel();
			return;
		}

		timer_->init();
		timer_->once<uvw::TimerEvent>([tunnel_uv = tunnel_](const uvw::TimerEvent&, uvw::TimerHandle & timer) {

#ifdef ALL_LOG
			LOG(INFO) << "conn timer com";
#endif
			auto tunnel = tunnel_uv.lock();
			if (tunnel == nullptr) return;

			tunnel->closeTunnel();
		});

		timer_->start(uvw::TimerHandle::Time(llsrv->getConfig()->idle_timeout), uvw::TimerHandle::Time(0));
	}

	void StopTimer() {
		timer_->stop();
	}

	std::shared_ptr<uvw::TcpHandle>   handle_;
	std::shared_ptr<uvw::TimerHandle> timer_;  // test timeout
	std::weak_ptr<T> tunnel_;
};


}  // ssr

#endif  // base_conn_h