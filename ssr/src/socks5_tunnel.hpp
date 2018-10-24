#ifndef socks5_tunnel_h
#define socks5_tunnel_h

// system
#include <assert.h>

// common
#include <ssr_common.h>

// uvw
#include <uvw.hpp>

// server
#include <local_server.hpp>
#include <base_tunnel.hpp>
#include <socks5_conn.hpp>
#include <ssr_tunnel_cipher.hpp>
#include <ssr_buffer.hpp>
#include <encrypt/executive.h>

// 3rd
#include <s5.h>


namespace ssr {
    
	class LocalServer;

class Socks5Tunnel: 
	public BaseTunnel<Socks5Tunnel, Socks5Conn, LocalServer> {

public:
	explicit Socks5Tunnel(std::weak_ptr<LocalServer> server):
		BaseTunnel<Socks5Tunnel, Socks5Conn, LocalServer>(server) {
#ifdef ALL_LOG
		LOG(INFO) << "Socks5Tunnel Construction";
#endif
	};
	virtual ~Socks5Tunnel() {

#ifdef ALL_LOG
		LOG(INFO) << "Socks5Tunnel Deconstruction";
#endif

		if (Socks5Tunnel::checkHandle(incoming_) && !incoming_->handle_->closing())
			incoming_->handle_->close();

		if (Socks5Tunnel::checkHandle(outgoing_) && !outgoing_->handle_->closing())
			outgoing_->handle_->close();
	};

	void init() {
	    // do nothing
	};

	void tunnelConnected(std::shared_ptr<uvw::TcpHandle>& handle) {
		std::shared_ptr<LocalServer> srv = Server().lock();
		if (srv == nullptr)
			return;

		auto timer = srv->Loop()->resource<uvw::TimerHandle>();

		if (incoming_ == nullptr) {		
			incoming_ = createConn(handle, timer);
			assert(incoming_ != nullptr);

			incoming_->RunTimeOut();
			s5_init(&s5ctx_);
			incoming_->state_ = session_state::session_handshake;
		}
		else if(outgoing_ == nullptr) {
			outgoing_ = createConn(handle, timer);
			assert(outgoing_ != nullptr);

			outgoing_->RunTimeOut();
			outgoing_->state_ = session_state::session_init;
		}
		else{
			abort();
		}
	}

	// reserve
	bool can_auth_none() {
		return true;
	}

    // reserve
	bool can_auth_passwd() {
		return false;
	}

	// reserve
	void do_handshake_auth() {
		closeTunnel();
	}

    // Forwarding  data
	void do_streaming(const uvw::DataEvent &event, std::shared_ptr<Socks5Conn>& conn) {
		auto buffer = std::make_shared<SSRBuffer>(SSR_BUFF_SIZE);
		assert(buffer != nullptr);

		buffer->write(event.data.get(), event.length);

		if (conn == outgoing_)
		{
			if (ssr_ok != tunnel_cipher_client_decrypt(buffer, tunnel_cipher_))
				return;

			incoming_->handle_->write(buffer->get(), buffer->len());
		}
		else
		if (conn == incoming_) {
			if (ssr_ok != tunnel_cipher_client_encrypt(buffer, tunnel_cipher_))
				return;

			outgoing_->handle_->write(buffer->get(), buffer->len());
		}
		else
		{
			abort();
		}
	}

	void do_ssr_auth_sent(const uvw::DataEvent &event, std::shared_ptr<Socks5Conn>& conn) {

		// just go to the next state

		// if (tunnel_cipher_client_need_feedback(tunnel_cipher_)) {
		// 	ctx->state = session_ssr_waiting_feedback;
		// 	do_ssr_receipt_for_feedback(event, conn);
		// }
		// else {
			do_socks5_reply_success();
		// }
	}

	void do_socks5_reply_success() {
		 // notify local browser, success
		std::unique_ptr<char[]> inWrite(new char[10]{ '\5', '\0','\0','\1','\0','\0','\0','\0','\0','\0' });		
		incoming_->handle_->write(std::move(inWrite), 10);
		incoming_->state_ = session_streaming;
		outgoing_->state_ = session_streaming;
	}


	void do_parse_s5_request(const uvw::DataEvent &event, std::shared_ptr<Socks5Conn>& conn) {
		uint8_t *data = (uint8_t *)event.data.get();
		size_t size = event.length;
		enum s5_err err = s5_parse(&s5ctx_, &data, &size);

		if (err == s5_ok) {
			conn->state_ = session_s5_request;  /* Need more data. */
			return;
		}

		if (size != 0) {
#ifdef HAVE_LOG
			LOG(ERROR) << "junk in request" << size;
#endif
			closeTunnel();
			return;
		}

		if (err != s5_exec_cmd) {
#ifdef HAVE_LOG
			LOG(ERROR) << "request error: " << s5_strerror(err);
#endif
			closeTunnel();
			return;
		}

		if (s5ctx_.cmd == s5_cmd_tcp_bind) {
			/* Not supported but relatively straightforward to implement. */
#ifdef HAVE_LOG
			LOG(ERROR) << "BIND requests are not supported." << size;
#endif
			closeTunnel();
			return;
		}

		if (s5ctx_.cmd == s5_cmd_udp_assoc) {

			// no support udp
			closeTunnel();
			return;
		}

		assert(s5ctx_.cmd == s5_cmd_tcp_connect);

		// connect remote, submit asynchronous DNS request
		{

			auto aeinfo = conn->handle_->loop().resource<uvw::GetAddrInfoReq>();
			auto timer = conn->handle_->loop().resource<uvw::TimerHandle>();


			aeinfo->on<uvw::ErrorEvent>([](const uvw::ErrorEvent&, uvw::GetAddrInfoReq &req) {
#ifdef HAVE_LOG
				LOG(ERROR) << "req error ";
#endif
			});


			aeinfo->once<uvw::AddrInfoEvent>([timer_uv = std::weak_ptr<uvw::TimerHandle>(timer),
				tunnel_uv = std::weak_ptr<Socks5Tunnel>(shared_from_this())]
			(const uvw::AddrInfoEvent& ae, uvw::GetAddrInfoReq &req) {

				auto timer = timer_uv.lock();
				if (timer != nullptr)
					timer->close();

				auto addr = (struct sockaddr_in *)ae.data.get()->ai_addr;

				auto tcp = req.loop().resource<uvw::TcpHandle>();

				tcp->on<uvw::ErrorEvent>([=](const uvw::ErrorEvent &, uvw::TcpHandle &) {
#ifdef HAVE_LOG
					LOG(ERROR) << "remote tcp error ";
#endif
					auto tunnel = tunnel_uv.lock();
					if (tunnel == nullptr) {
						return;
					}
					tunnel->closeTunnel();
				});

				tcp->on<uvw::DataEvent>([=](const uvw::DataEvent &event, uvw::TcpHandle & handle) {

					auto tunnel = tunnel_uv.lock();
					if (tunnel == nullptr) {
						return;
					}
					tunnel->tunnelRecved(event, handle);
				});

				tcp->on<uvw::WriteEvent>([=](const uvw::WriteEvent &event, uvw::TcpHandle &handle) {
					auto tunnel = tunnel_uv.lock();
					if (tunnel == nullptr) return;

					tunnel->tunnelWrited(handle);
				});

				tcp->once<uvw::ConnectEvent>([=](const uvw::ConnectEvent &, uvw::TcpHandle &handle) {


					auto tunnel = tunnel_uv.lock();
					if (tunnel == nullptr) return;

					auto lserver = tunnel->Server().lock();
					if (lserver == nullptr) return;

					assert(Socks5Tunnel::checkHandle(tunnel->outgoing_));
					tunnel->outgoing_->StopTimer();

					// initialization encryption and decryption protocol
					auto server_cipher = lserver->getCipher();
					assert(server_cipher != nullptr);
					tunnel->tunnel_cipher_ = std::make_shared<TunnelCipher>(server_cipher, 1452);
					assert(tunnel->tunnel_cipher_ != nullptr && tunnel->s5ctx_.cmd != 0);

					// build initialization package
					auto buffer = initial_package_create(&tunnel->s5ctx_);

					// encrypt init package and send to ssr server
					if (ssr_ok != tunnel_cipher_client_encrypt(buffer, tunnel->tunnel_cipher_)) {
						return;
					}

					assert(tunnel->outgoing_->handle_->writable());
					tunnel->outgoing_->handle_->write(buffer->get(), buffer->len());
					tunnel->outgoing_->RunTimeOut();
					tunnel->outgoing_->state_ = session_ssr_auth_sent;
					

					handle.read();
					tunnel->do_socks5_reply_success();

				});

				tcp->once<uvw::CloseEvent>([=](const uvw::CloseEvent &, uvw::TcpHandle &) {
					auto tunnel = tunnel_uv.lock();
					if (tunnel == nullptr) return;
				});

				 auto tunnel = tunnel_uv.lock();
				 if (tunnel == nullptr) return;

				 auto server = tunnel->Server().lock();
				 if (server == nullptr) return;

				// connect ssr server
				 tcp->connect(server->getConfig()->remote_host, server->getConfig()->remote_port);

				// timeout check
				tunnel->tunnelConnected(tcp);
			});




			timer->once<uvw::TimerEvent>([aeinfo_uv = std::weak_ptr<uvw::GetAddrInfoReq>(aeinfo),
				tunnel_uv = std::weak_ptr<Socks5Tunnel>(shared_from_this())]
				
				(const uvw::TimerEvent&, uvw::TimerHandle & timer) {


				auto aeinfo = aeinfo_uv.lock();
				if (aeinfo != nullptr)
					aeinfo->cancel();
#ifdef ALL_LOG
				LOG(INFO) << "DNS timer";
#endif
				auto tunnel = tunnel_uv.lock();
				if (tunnel == nullptr) return;

				tunnel->closeTunnel();
			});

			timer->init();
			auto llsrv = Server().lock();
			if (llsrv == nullptr) {
				closeTunnel();
				return;
			}

#ifdef HAVE_LOG
			LOG(INFO) << "current url: " << s5ctx_.daddr;
#endif

#ifdef ENABLE_RE_RULES
			if (llsrv->Match((char*)s5ctx_.daddr)) {		
				closeTunnel();
				return;
			}
#endif
			
			aeinfo->nodeAddrInfo(std::string((char*)s5ctx_.daddr));
			timer->start(uvw::TimerHandle::Time(llsrv->getConfig()->idle_timeout), uvw::TimerHandle::Time(0));

			// not allow recv
			incoming_->state_ = session_kill;
		}

	}

	void do_wait_s5_request(std::shared_ptr<Socks5Conn>& conn) {
		conn->state_ = session_s5_request;
	}

	void do_handshake(const uvw::DataEvent &event, std::shared_ptr<Socks5Conn>& conn) {
		uint8_t *data = (uint8_t *)event.data.get();
		size_t size = event.length;
		enum s5_err err = s5_parse(&s5ctx_, &data, &size);
		if (err == s5_ok) {
			conn->state_ = session_handshake;  /* Need more data. */
			return;
		}

		if (size != 0) {
			/* Could allow a round-trip saving shortcut here if the requested auth
			* method is s5_auth_none (provided unauthenticated traffic is allowed.)
			* Requires client support however.
			*/
#ifdef HAVE_LOG
			LOG(ERROR) << "junk in handshake" << size;
#endif
			closeTunnel();
			return;
		}

		if (err != s5_auth_select) {
#ifdef HAVE_LOG
			LOG(ERROR) << "handshake error:" << s5_strerror(err);
#endif
			closeTunnel();
			return;
		}

		enum s5_auth_method methods = s5_auth_methods(&s5ctx_);
		if ((methods & s5_auth_none) && can_auth_none()) {
			s5_select_auth(&s5ctx_, s5_auth_none);

		    auto dataWrite = std::unique_ptr<char[]>(new char[2]{ '\5', '\0' });
			conn->handle_->write(std::move(dataWrite), 2);
			conn->state_ = session_handshake_replied;
			return;
		}

		if ((methods & s5_auth_passwd) && can_auth_passwd()) {
			/* TODO(bnoordhuis) Implement username/password auth. */
			closeTunnel();
			return;
		}

		auto dataWrite = std::unique_ptr<char[]>(new char[2]{ '\5', '\377' });
		conn->handle_->write(std::move(dataWrite), 2);
		conn->state_ = session_state::session_kill;

	}

	void donext(const uvw::DataEvent &event, std::shared_ptr<Socks5Conn>& conn) {
		// process

		// some states is not used.
		switch (conn->state_) {
		case session_state::session_handshake:
			assert(conn == incoming_);
			conn->StopTimer();
			do_handshake(event, conn);
			break;
		case session_state::session_handshake_auth:
			do_handshake_auth();
			break;
		case session_state::session_handshake_replied:
			do_wait_s5_request(conn);
			// break;
		case session_state::session_s5_request:
			do_parse_s5_request(event, conn);
			break;
		case session_state::session_s5_udp_accoc:
			break;
		case session_state::session_resolve_ssr_server_host:
			break;
		case session_state::session_connect_ssr_server: // outgoing ==> initial state
			break;
		case session_state::session_ssr_auth_sent:      // outgoing ==> after sending the first package
			assert(conn == outgoing_);
			conn->StopTimer();
			do_ssr_auth_sent(event, conn);
			break;
		case session_state::session_ssr_waiting_feedback:
			break;
		case session_state::session_ssr_receipt_of_feedback_sent:
			break;
		case session_state::session_auth_complition_done:
			break;
		case session_state::session_streaming:
			conn->StopTimer();
			do_streaming(event, conn);
			conn->RunTimeOut();
			break;
		case session_state::session_kill:
			closeTunnel();
			break;
		default:
			abort();
		}
	}

	void tunnelWrited(uvw::TcpHandle& handle) {
		// donothing
	}

	void tunnelRecved(const uvw::DataEvent &event, uvw::TcpHandle &handle) {
		
		// 
		if (Socks5Tunnel::checkHandle(incoming_) && &handle == incoming_->handle_.get()) donext(event, incoming_);
		else if (Socks5Tunnel::checkHandle(outgoing_) && &handle == outgoing_->handle_.get()) donext(event, outgoing_);
	}

	static inline bool checkHandle(std::shared_ptr<Socks5Conn>& conn) {
		return (conn != nullptr && conn->handle_ != nullptr);
	}

private:
	std::shared_ptr<Socks5Conn> incoming_;
	std::shared_ptr<Socks5Conn> outgoing_;

	// for s5_parse
	s5_ctx s5ctx_;

	// for d/entrypt
	std::shared_ptr<TunnelCipher> tunnel_cipher_;
};


}  // ssr

#endif  // socks5_tunnel_h