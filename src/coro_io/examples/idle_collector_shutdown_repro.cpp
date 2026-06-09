#include <async_simple/coro/SyncAwait.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <thread>

#include "ylt/coro_io/client_pool.hpp"
#include "ylt/coro_io/coro_io.hpp"
#include "ylt/coro_rpc/coro_rpc_server.hpp"
#include "ylt/coro_rpc/impl/coro_rpc_client.hpp"

using namespace std::chrono_literals;

namespace {

int get_env_int(const char* name, int fallback) {
  if (const char* value = std::getenv(name); value != nullptr && value[0] != '\0') {
    return std::atoi(value);
  }
  return fallback;
}

}  // namespace

int main() {
  const int port = get_env_int("YLT_REPRO_PORT", 18801);
  const int idle_timeout_ms = get_env_int("YLT_REPRO_IDLE_TIMEOUT_MS", 3000);
  const int warmup_sleep_ms = get_env_int("YLT_REPRO_WARMUP_SLEEP_MS", 20);

  std::cout << "port=" << port << '\n';
  std::cout << "idle_timeout_ms=" << idle_timeout_ms << '\n';
  std::cout << "warmup_sleep_ms=" << warmup_sleep_ms << '\n';

  coro_rpc::coro_rpc_server server(1, static_cast<uint16_t>(port));
  auto started = server.async_start();
  if (started.hasResult()) {
    std::cerr << "server failed to start\n";
    return 2;
  }

  auto io_pool = std::make_shared<coro_io::io_context_pool>(1);
  std::thread runner([io_pool] {
    io_pool->run();
  });

  auto pool = coro_io::client_pool<coro_rpc::coro_rpc_client>::create(
      std::string("127.0.0.1:") + std::to_string(port),
      {.max_connection = 1,
       .idle_timeout = std::chrono::milliseconds(idle_timeout_ms),
       .short_connect_idle_timeout = std::chrono::milliseconds(idle_timeout_ms)},
      *io_pool);

  async_simple::coro::syncAwait([&]() -> async_simple::coro::Lazy<void> {
    auto ret = co_await pool->send_request(
        [](coro_rpc::coro_rpc_client&) -> async_simple::coro::Lazy<void> {
          co_return;
        });
    if (!ret.has_value()) {
      std::cerr << "send_request failed\n";
      std::exit(3);
    }
    co_await coro_io::sleep_for(std::chrono::milliseconds(warmup_sleep_ms));
  }());

  pool.reset();
  io_pool->stop();
  runner.join();
  server.stop();
  return 0;
}
