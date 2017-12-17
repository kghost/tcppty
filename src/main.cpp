#include "config.h"

#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <pty.h>
#include <libgen.h>

#define BOOST_LOG_USE_NATIVE_SYSLOG
#include <memory>
#include <iostream>
#include <vector>
#include <experimental/optional>
#include <boost/asio.hpp>
#include <boost/fusion/adapted/std_tuple.hpp>
#include <boost/fusion/include/for_each.hpp>
#include <boost/filesystem.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/keywords/auto_flush.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/sinks/syslog_backend.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/system/error_code.hpp>

#include "protocol.h"

class forwarder;
std::map<pid_t, std::shared_ptr<forwarder>> processes;

class forwarder : public std::enable_shared_from_this<forwarder> {
	public:
		forwarder(boost::asio::io_service& io_service) : io_service(io_service), sock(io_service) {}

		void start() {
			std::stringstream ss;
			ss << "forwarder(" << sock.remote_endpoint() << " => " << sock.local_endpoint() << ") ";
			tag = ss.str();

			::fcntl(sock.native_handle(), F_SETFD, FD_CLOEXEC);
			sock.non_blocking(true);
			const auto options = std::make_tuple(
				boost::asio::ip::tcp::no_delay(true)
				);
			boost::fusion::for_each(options, [this](auto option) { sock.set_option(option); });
			auto endpoint = sock.local_endpoint();
			read_socket(std::make_shared<std::vector<char>>());
		}

		bool process_exited(int wstatus) {
			if (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus)) return false;

			BOOST_LOG_TRIVIAL(info) << tag << " process exited: " << wstatus;
			auto msg = std::make_shared<Pty::Message>();
			msg->type = Pty::Message::TYPE_EXIT;
			msg->xid = 0;
			msg->flags = 0;

			Pty::Exit exit;
			exit.exited = WIFEXITED(wstatus);
			exit.signaled = WIFSIGNALED(wstatus);
			exit.exit_status = WEXITSTATUS(wstatus);
			exit.terminate_signal = WTERMSIG(wstatus);
			auto v = std::make_shared<std::vector<char>>(exit.space());
			exit.marshal(&*v->begin(), &*v->end());

			writeMessage(msg, &*v->begin(), v->size(), [me = shared_from_this(), v] {
				me->sock.close();
				std::get<1>(me->child.value()).close();
			});

			return true;
		}

		boost::asio::ip::tcp::socket sock;
	private:
		void read_socket(std::shared_ptr<std::vector<char>> pre) {
			auto msg = std::make_shared<Pty::Message>();
			boost::asio::async_read(sock, boost::asio::buffer(msg.get(), sizeof(Pty::Message)),
				[me = shared_from_this(), pre, msg](const boost::system::error_code& ec, std::size_t bytes_transferred) {
					if (ec || bytes_transferred == 0) {
						BOOST_LOG_TRIVIAL(error) << me->tag << " read socket error: " << ec.message();
						me->sock.close();
						if (bool(me->child)) std::get<1>(me->child.value()).close();
						return;
					}

					auto data = std::make_shared<std::vector<char>>(msg->length);
					boost::asio::async_read(me->sock, boost::asio::buffer(*data),
						[me, pre, msg, data](const boost::system::error_code& ec, std::size_t bytes_transferred) {
							if (ec) {
								BOOST_LOG_TRIVIAL(error) << me->tag << " read socket data error: " << ec.message();
								me->sock.close();
								if (bool(me->child)) std::get<1>(me->child.value()).close();
								return;
							}

							if (msg->flags & Pty::Message::FLAG_CONTINUE) {
								pre->insert(pre->end(), data->begin(), data->end());
								me->read_socket(pre);
								return;
							}

							if (pre->empty()) {
								me->handleMessage(*msg, std::move(*data));
							} else {
								pre->insert(pre->end(), data->begin(), data->end());
								me->handleMessage(*msg, std::move(*pre));
							}
						});
				});
		}

		void handleMessage(const Pty::Message& msg, std::vector<char>&& data) {
			switch (msg.type) {
				case Pty::Message::TYPE_DATA:
					if (!bool(child)) break;
					boost::asio::async_write(std::get<1>(child.value()), boost::asio::buffer(data),
						[me = shared_from_this()](const boost::system::error_code& ec, std::size_t bytes_transferred) {
							if (ec) {
								BOOST_LOG_TRIVIAL(error) << me->tag << " write pty error: " << ec.message();
								std::get<1>(me->child.value()).close();
								return;
							}

							me->read_socket(std::make_shared<std::vector<char>>());
						});
					break;
				case Pty::Message::TYPE_EXEC:
					{
						Pty::Exec exec;
						exec.unmarshal(&*data.begin(), &*data.end());
						int amaster;
						struct winsize winsize;
						winsize.ws_row = win.rows;
						winsize.ws_col = win.cols;
						winsize.ws_xpixel = 0;
						winsize.ws_ypixel = 0;
						auto p = ::forkpty(&amaster, nullptr, nullptr, &winsize);
						if (p < 0) {
							auto err = ::strerror(errno);
							BOOST_LOG_TRIVIAL(error) << tag << " fork pty failed: " << err;
						} else if (p > 0) {
							// parent
							::fcntl(amaster, F_SETFD, FD_CLOEXEC);
							processes[p] = shared_from_this();
							child.emplace(p, boost::asio::posix::stream_descriptor(io_service, amaster));
							read_pty();
						} else {
							// child
							char *prog;
							if (exec.prog.s.empty()) {
								auto pw = ::getpwuid(::getuid());
								if (pw != nullptr) {
									::chdir(pw->pw_dir);
									prog = pw->pw_shell;
								} else prog = ::strdup("/bin/sh");
							} else {
								prog = ::strdup(exec.prog.s.c_str());
							}

							std::string args_store;
							std::vector<const char*> args;
							if (exec.args.empty()) {
								// act as login shell
								args_store = std::string("-") + basename(prog);
								args.push_back(args_store.c_str());
								args.push_back(nullptr);
							} else {
								std::for_each(exec.args.begin(), exec.args.end(), [&](auto& e) { args.push_back(e.s.c_str()); });
								args.push_back(nullptr);
							}

							std::for_each(exec.envs.begin(), exec.envs.end(), [&](auto& e) {
								::setenv(std::get<0>(e).s.c_str(), std::get<1>(e).s.c_str(), true);
							});
							::execvp(prog, const_cast<char* const*>(&*args.begin()));
						}
					}
					read_socket(std::make_shared<std::vector<char>>());
					break;
				case Pty::Message::TYPE_WINCH:
					win.unmarshal(&*data.begin(), &*data.end());
					if (bool(child)) {
						struct winsize winsize;
						winsize.ws_row = win.rows;
						winsize.ws_col = win.cols;
						ioctl(std::get<1>(child.value()).native_handle(), TIOCSWINSZ, &winsize);
					}
					read_socket(std::make_shared<std::vector<char>>());
					break;
				default:
					BOOST_LOG_TRIVIAL(error) << tag << " unknown message: " << msg.type;
					read_socket(std::make_shared<std::vector<char>>());
					break;
			}
		}

		void read_pty() {
			auto buf = std::make_shared<std::array<char, 4096>>();
			std::get<1>(child.value()).async_read_some(boost::asio::buffer(*buf),
				[me = shared_from_this(), buf](const boost::system::error_code& ec, std::size_t bytes_transferred) {
					if (ec || bytes_transferred == 0) {
						BOOST_LOG_TRIVIAL(error) << me->tag << " read pty error: " << ec.message();
						std::get<1>(me->child.value()).close();
						return;
					}

					auto msg = std::make_shared<Pty::Message>();
					msg->type = Pty::Message::TYPE_DATA;
					msg->xid = 0;
					msg->flags = 0;

					me->writeMessage(msg, buf->data(), bytes_transferred, [me, buf] {
						me->read_pty();
					});
				});
		}

		void writeMessage(std::shared_ptr<Pty::Message> msg, char* data, std::size_t size, std::function<void()>&& callback) {
			if (size == 0) {
				callback();
				return;
			}
			if (size >= (1<<16)) msg->length = -1;
			else msg->length = size;

			boost::asio::async_write(sock,
				std::vector<boost::asio::const_buffer>{
					boost::asio::buffer(msg.get(), sizeof(*msg)),
					boost::asio::buffer(data, msg->length),
				},
				[me = shared_from_this(), msg, data, size, callback = std::move(callback)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
					if (ec) {
						BOOST_LOG_TRIVIAL(error) << me->tag << " write socket error: " << ec.message();
						me->sock.close();
						std::get<1>(me->child.value()).close();
						return;
					}

					me->writeMessage(msg, data + msg->length, size - msg->length, std::move(callback));
				});
		}

		Pty::WinSize win;
		boost::asio::io_service& io_service;
		std::experimental::optional<std::tuple<pid_t, boost::asio::posix::stream_descriptor>> child;
		std::string tag;
};

class listener : public std::enable_shared_from_this<listener> {
	public:
		listener(boost::asio::io_service &io_service)
		: io_service(io_service), socket(io_service) {}

		void start() {
			try {
				boost::asio::ip::tcp::endpoint e(
					boost::asio::ip::address::from_string("127.0.0.1"), 0
				);
				socket.open(e.protocol());
				if (e.protocol().family() == AF_INET6)
					socket.set_option(boost::asio::ip::v6_only(true));
				boost::asio::socket_base::reuse_address option(true);
				::fcntl(socket.native_handle(), F_SETFD, FD_CLOEXEC);
				socket.set_option(option);
				socket.bind(e);
				socket.listen();
				auto local = socket.local_endpoint();
				std::cout << local.port() << std::endl;
			} catch (const boost::system::system_error &e) {
				BOOST_LOG_TRIVIAL(error) << " start failed: " << e.what();
				return;
			}
			loop();
		}

		void close() {
			socket.close();
		}
	private:
		void loop() {
			auto f = std::make_shared<forwarder>(io_service);
			socket.async_accept(f->sock, [me = shared_from_this(), f](const boost::system::error_code& ec) {
				if (!ec) {
					f->start();
					me->loop();
				} else {
					BOOST_LOG_TRIVIAL(error) << "accept error: " << ec.message();
				}
			});
		}

		boost::asio::io_service &io_service;
		boost::asio::ip::tcp::acceptor socket;
};

void singal_handler(boost::asio::signal_set& signals, boost::asio::io_service& io_service) {
	signals.async_wait([&signals, &io_service](const boost::system::error_code& ec, int signal_number) {
		if (!ec) {
			switch (signal_number) {
				case SIGINT:
				case SIGTERM:
					io_service.stop();
					break;
				case SIGHUP:
				case SIGPIPE:
					break;
				case SIGCHLD:
					for (;;) {
						int wstatus;
						auto pid = ::waitpid(-1, &wstatus, WNOHANG);
						if (pid <= 0) break;
						auto it = processes.find(pid);
						if (it != processes.end() && it->second->process_exited(wstatus))
							processes.erase(it);
					}
					break;
			}
			singal_handler(signals, io_service);
		} else {
			BOOST_LOG_TRIVIAL(error) << "Sighandler error: " << ec.message();
		}
	});
}

void read_and_discard_stdin(boost::asio::posix::stream_descriptor& in, std::function<void()>&& exit) {
	auto buf = std::make_shared<std::array<char, 4096>>();
	in.async_read_some(boost::asio::buffer(*buf),
	[&in, buf, exit = std::move(exit)](const boost::system::error_code& ec, std::size_t bytes_transferred) mutable {
		if (ec || bytes_transferred == 0) {
			BOOST_LOG_TRIVIAL(info) << "stdin error/end: " << ec.message();
			exit();
			return;
		}

		read_and_discard_stdin(in, std::move(exit));
	});
}

int main (int ac, char **av) {
	boost::log::add_console_log(std::clog, boost::log::keywords::auto_flush = true);

	struct rlimit nofile;
	nofile.rlim_cur = 65536;
	nofile.rlim_max = 65536;
	int rc = setrlimit(RLIMIT_NOFILE, &nofile);
	if (rc < 0) {
		char e[200];
		BOOST_LOG_TRIVIAL(warning) << "setrlimit: " << strerror_r(errno, e, sizeof(e));
	}

	::unsetenv("TERM");
	::unsetenv("SHELL");

	boost::asio::io_service io_service;

	boost::asio::signal_set signals(io_service);
	signals.add(SIGINT);
	signals.add(SIGTERM);
	signals.add(SIGPIPE);
	signals.add(SIGCHLD);
	singal_handler(signals, io_service);

	auto l = std::make_shared<listener>(io_service);
	l->start();

	boost::asio::posix::stream_descriptor i(io_service, ::dup(STDIN_FILENO));
	read_and_discard_stdin(i, [&]{ io_service.stop(); });

	io_service.run();

	boost::log::core::get()->remove_all_sinks();

	return 0;
}
