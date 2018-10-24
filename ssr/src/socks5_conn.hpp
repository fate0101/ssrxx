#ifndef socks5_conn_h
#define socks5_conn_h

// system
#include <memory>
#include <iostream>

// common
#include <ssr_common.h>

// server
#include <base_conn.hpp>


namespace ssr {

	/* Session states. */
	enum session_state {
		session_init,             //  init state
		session_handshake,        /* Wait for client handshake. */
		session_handshake_auth,   /* Wait for client authentication data. */
		session_handshake_replied,        /* Start waiting for request data. */
		session_s5_request,        /* Wait for request data. */
		session_s5_udp_accoc,
		session_resolve_ssr_server_host,       /* Wait for upstream hostname DNS lookup to complete. */
		session_connect_ssr_server,      /* Wait for uv_tcp_connect() to complete. */
		session_ssr_auth_sent,
		session_ssr_waiting_feedback,
		session_ssr_receipt_of_feedback_sent,
		session_auth_complition_done,      /* Connected. Start piping data. */
		session_streaming,            /* Connected. Pipe data back and forth. */
		session_kill,                 /* Tear down session. */
	};

class Socks5Tunnel;

class Socks5Conn: public BaseConn<Socks5Tunnel> {
public:
	explicit Socks5Conn(std::shared_ptr<uvw::TcpHandle>   handle,
		std::shared_ptr<uvw::TimerHandle> timer,
		std::weak_ptr<Socks5Tunnel> tunnel) 
		: BaseConn<Socks5Tunnel>(handle, timer, tunnel), state_(ssr::session_handshake) {
#ifdef ALL_LOG
		LOG(INFO) << "Socks5Conn Construction";
#endif
	};

	~Socks5Conn() {
#ifdef ALL_LOG
		LOG(INFO) << "Socks5Conn Deconstruction";
#endif
	};

	// record session state
	session_state state_;
};


}  // ssr

#endif  // socks5_conn_h