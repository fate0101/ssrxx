// system
#include <thread>

// commom
#include <ssr.hpp>

#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

#ifdef _DEBUG // replace new  
#define new  new(_NORMAL_BLOCK, __FILE__, __LINE__)    
#endif

//////////////////////////////////////////////////////////////////////////
// may have some error
void TestChangeConfig(std::shared_ptr<ssr::LocalServer> linster_server) {
	std::thread([=]()->void {
		bool change_symbol = true;
		do {
			if (change_symbol) {
				auto local_config = std::make_shared<ssr::Config>();
				local_config->listen_host = "0.0.0.0";
				local_config->listen_port = 8080;
				local_config->remote_host = "127.0.0.1";
				local_config->remote_port = 8888;
				local_config->password = "pass";
				local_config->method = "aes-256-cfb";
				local_config->protocol = "origin";
				local_config->protocol_param = "";
				local_config->obfs = "plain";
				local_config->obfs_param = "";
				local_config->udp = false;
				local_config->idle_timeout = 300000;

				linster_server->setConfig(local_config);
			}
			else {
				auto remote_config = std::make_shared<ssr::Config>();
				remote_config->listen_host = "0.0.0.0";
				remote_config->listen_port = 8080;
				remote_config->remote_host = "127.0.0.1";
				remote_config->remote_port = 8889;
				remote_config->password = "pass";
				remote_config->method = "aes-256-cfb";
				remote_config->protocol = "origin";
				remote_config->protocol_param = "";
				remote_config->obfs = "plain";
				remote_config->obfs_param = "";
				remote_config->udp = false;
				remote_config->idle_timeout = 300000;
				linster_server->setConfig(remote_config);
			}
			change_symbol = !change_symbol;
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		} while (1000);
	}).detach();
}



int main() {
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	{
#ifdef HAVE_LOG
		logging::LoggingSettings settings;
#ifdef _DEBUG
		settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
#else
		settings.logging_dest = logging::LOG_NONE;
#endif
		settings.log_file = L"";
		logging::InitLogging(settings);

		// logging setting
		logging::SetLogItems(false, true, false, false);
#endif
		auto srv = std::make_shared<ssr::LocalServer>();
		
#ifdef ENABLE_RE_RULES
		srv->setRules(ssr::SSRRULE{"google"});
#endif

		auto config = std::make_shared<ssr::Config>();
		config->listen_host = "0.0.0.0";
		config->listen_port = 8080;
		config->remote_host = "127.0.0.1";
		config->remote_port = 8888;
		config->password = "pass";
		config->method = "aes-256-cfb";

		// just support auth_sha1_v4 and default
		config->protocol = "auth_sha1_v4";
		config->protocol_param = "";
		config->obfs = "plain";
		config->obfs_param = "";
		config->udp = false;
		config->idle_timeout = 300000;

		
		srv->Init(std::move(config));
		

		auto sigint = srv->Loop()->resource<uvw::SignalHandle>();

		auto quit = [ss = std::weak_ptr<ssr::LocalServer>(srv)](const uvw::SignalEvent &event, uvw::SignalHandle & handle) {
			handle.close();

			auto srv = ss.lock();
			if (srv == nullptr) return;
			srv->Loop()->stop();
		};

		sigint->once<uvw::SignalEvent>(quit);
		sigint->start(SIGINT);

#ifdef TEST
		// test change config
		TestChangeConfig(srv);
#endif

		srv->Run();

		do {
			std::cout << "server use cout:" << srv.use_count() << std::endl;

			// wait some time
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		} while (srv.use_count() > 1);
		srv->Loop()->close();
	}
	
	system("pause");
	return 0;
}