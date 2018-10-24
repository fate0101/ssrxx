#ifndef base_server_hpp
#define base_server_hpp

// system
#include <assert.h>
#include <set>
#include <memory>
#include <iostream>

// common
#include <ssr_common.h>
#include <ssr_config.hpp>

// uvw
#include <uvw.hpp>

#ifdef ENABLE_RE_RULES
// RE2
#include <re2/re2.h>
#include <re2/set.h>
#endif

// server
#include <noncopyable.hpp>


namespace ssr {

	using SSRRULE = std::vector<std::string>;

template <class TR, class T>
class BaseServer: 
	public noncopyable, public std::enable_shared_from_this<TR> {

public:
	using SSRTHIS = std::enable_shared_from_this <TR>;
	

	explicit BaseServer() {
	};

	virtual ~BaseServer() {
		clearTunnel();
	};

public:
#ifdef ENABLE_RE_RULES
	bool setRules(SSRRULE&& rules) {

		auto des_rules = std::make_shared<RE2::Set>(RE2::DefaultOptions, RE2::UNANCHORED);
		assert(des_rules);

		for (auto rule : rules) {
			if (des_rules->Add(rule, NULL) == -1) return false;
		}	

		if (!des_rules->Compile())
			return false;

		rules_.swap(des_rules);
		return true;
	}

	bool Match(std::string&& text) {
		if (rules_ == nullptr)
			return false;

		return rules_->Match(text, NULL);
	}
#endif

public:
	virtual unsigned short Init(std::shared_ptr<Config>&& config) {
		listen_host_ = config->listen_host;
	    listen_port_ = config->listen_port;
		setConfig(config);
		loop_ = uvw::Loop::getDefault();
		return listen();
	}

	void Run() {
		loop_->run();
	}

	const std::shared_ptr<Config> getConfig() {
		return config_;
	}

	virtual void setConfig(std::shared_ptr<Config> config) {
		std::swap(config_, config);
	}

	std::shared_ptr<uvw::Loop> Loop() {
		return loop_;
	}

	void closeTunnel(std::shared_ptr<T> tunnel) {
		assert(tunnels_.find(tunnel) != tunnels_.end());
		deleteTunnel(tunnel);
	}

protected:
	std::shared_ptr<T> createTunnel() {
		auto tunnel = std::make_shared<T>(std::weak_ptr<TR>(SSRTHIS::shared_from_this()));
		assert(tunnel != nullptr);

		if (addTunnel(tunnel)) {
			// tunnel->init();
			return tunnel;
		}
		else {
			abort();
			return tunnel;
		}
	}

	unsigned short listen() {
		std::shared_ptr<uvw::TcpHandle> tcp = loop_->resource<uvw::TcpHandle>();

		tcp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &, uvw::TcpHandle &) {
#ifdef HAVE_LOG
			LOG(ERROR) << "listener error ";
#endif
			// maybe, emm..
			abort();
		});

		tcp->on<uvw::ListenEvent>([lsvr = 
			std::weak_ptr<TR>(SSRTHIS::shared_from_this())]
			(const uvw::ListenEvent &, uvw::TcpHandle &lhandle) {

			auto llsrv = lsvr.lock();
			if (llsrv == nullptr) {
				// loop break
				lhandle.loop().stop();
				return;
			}

			// create tunnel
			std::shared_ptr<T> tunnel = llsrv->createTunnel();
			std::weak_ptr<T> weak_tunnel = std::weak_ptr<T>(tunnel);

			std::shared_ptr<uvw::TcpHandle> client = lhandle.loop().resource<uvw::TcpHandle>();

			client->on<uvw::ErrorEvent>([tunnel_uv = weak_tunnel](const uvw::ErrorEvent &, uvw::TcpHandle &) {
#ifdef HAVE_LOG
				LOG(ERROR) << "local tcp error";
#endif
				auto tunnel = tunnel_uv.lock();
				if (tunnel == nullptr) return;
				tunnel->closeTunnel();
			});



			client->on<uvw::CloseEvent>([tunnel_uv = weak_tunnel]
				(const uvw::CloseEvent &, uvw::TcpHandle &) {

				auto tunnel = tunnel_uv.lock();
				if (tunnel == nullptr) return;

				tunnel->closeTunnel();
			});

			lhandle.accept(*client);


			client->on<uvw::DataEvent>([tunnel_uv = weak_tunnel](const uvw::DataEvent &event, uvw::TcpHandle & handle) {

				auto tunnel = tunnel_uv.lock();
				if (tunnel == nullptr) {
					return;
				}
				tunnel->tunnelRecved(event, handle);
			});

			client->on<uvw::EndEvent>([](const uvw::EndEvent &, uvw::TcpHandle &handle) {

				// for debug
#ifdef ALL_LOG
				{
					LOG(INFO) << "end";
					int count = 0;
					handle.loop().walk([&count](uvw::BaseHandle &) { ++count; });
					LOG(INFO) << "still alive: " << count << " handles";
				}
#endif

				handle.close();
			});

			tunnel->tunnelConnected(client);

			client->read();
		});

		tcp->once<uvw::CloseEvent>([](const uvw::CloseEvent &, uvw::TcpHandle &handle) {
			handle.loop().stop();
		});

		// Only supports single ip binding
		// does not support domain name binding
		tcp->bind(listen_host_, listen_port_);

		tcp->listen();

		auto local = tcp->sock();
#ifdef HAVE_LOG
		LOG(INFO) << "local: " << local.ip << " " << local.port;
#endif
		return local.port;
	}

	bool addTunnel(std::shared_ptr<T>& tunnel) {

		if (tunnels_.find(tunnel) != tunnels_.end()) {
			abort();
			return false;
		}
		tunnels_.insert(tunnel);
		return true;
	}

	void deleteTunnel(std::shared_ptr<T> tunnel) {
		tunnels_.erase(tunnel);
	}

	void clearTunnel() {
		tunnels_.clear();
	}

protected:
	std::set<std::shared_ptr<T>>  tunnels_;
	std::shared_ptr<Config>       config_;

	std::shared_ptr<uvw::Loop>    loop_;
	std::string    listen_host_;
	unsigned short listen_port_;

#ifdef ENABLE_RE_RULES
	std::shared_ptr<RE2::Set> rules_;
#endif
};


}  // ssr

#endif  // base_server_hpp