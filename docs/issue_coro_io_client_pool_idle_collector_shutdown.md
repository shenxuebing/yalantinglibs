# Issue: `coro_io::client_pool` idle collector can leak coroutine frame or block shutdown for full `idle_timeout`

## Summary

`coro_io::client_pool` starts a background coroutine `collect_idle_timeout_client()` after a free client is returned to the pool.

When the owning `client_pool` is destroyed while that coroutine is sleeping inside:

```cpp
co_await coro_io::sleep_for(sleep_time);
```

shutdown has two bad outcomes depending on how the upper layer stops the executor:

1. force stop can leave the sleeping coroutine frame leaked
2. normal stop can block until the full `idle_timeout` expires

This is a library bug in the idle collector shutdown path rather than an application misuse issue.

## Affected code

Current logic is in:

- `include/ylt/coro_io/client_pool.hpp`
- function: `collect_idle_timeout_client(...)`

The problematic pattern is effectively:

```cpp
clients.reselect();
self = nullptr;
co_await coro_io::sleep_for(sleep_time);
if ((self = self_weak.lock()) == nullptr) {
  break;
}
```

The coroutine only checks whether the owner is gone after the full sleep finishes.

## Why this is a bug

The idle collector is started internally by `client_pool`, so its lifetime management should also be handled internally by `client_pool`.

Upper-layer code cannot cleanly solve this without depending on internal details like:

- whether the collector is running
- how long `idle_timeout` is
- whether force stop is safe
- how long it must wait before destruction

That makes this an ownership/lifecycle issue inside the library.

## Minimal reproduction

The issue can be reproduced with a local `coro_rpc_server`, a dedicated
`io_context_pool`, and a `client_pool` with a multi-second `idle_timeout`.

After one request returns a client to the pool, the idle collector starts
sleeping. Destroying the pool during that sleep reproduces the problem.

Standalone reproduction code:

```cpp
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
```

An equivalent standalone example is placed at:

- `src/coro_io/examples/idle_collector_shutdown_repro.cpp`

## How to build

WSL example build flow:

```bash
cd /mnt/e/vs2022workspace/yalantinglibs-bugrepro
rm -rf build-wsl
cmake -S . -B build-wsl -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZER=OFF
cmake --build build-wsl --target coro_io_example_idle_collector_shutdown_repro -j
```

## How to run

Recommended environment variables:

```bash
export YLT_REPRO_PORT=18801
export YLT_REPRO_IDLE_TIMEOUT_MS=5000
export YLT_REPRO_WARMUP_SLEEP_MS=100
```

Run under `valgrind`:

```bash
valgrind --leak-check=full --show-leak-kinds=all \
  ./build-wsl/output/examples/coro_io_example_idle_collector_shutdown_repro
```

`ENABLE_SANITIZER=OFF` is required here. If the example is linked with ASan, `valgrind` will report output like:

```text
ASan runtime does not come first in initial library list
total heap usage: 0 allocs, 0 frees, 0 bytes allocated
```

That result is not valid for leak reproduction.

Optionally, to observe the long-stop behavior more clearly:

```bash
time ./build-wsl/output/examples/coro_io_example_idle_collector_shutdown_repro
```

## Confirmed reproduction

The standalone reproducer has now been confirmed on WSL with `valgrind`
after rebuilding with `-DENABLE_SANITIZER=OFF`.

The key point is that the bug is reproducible in `yalantinglibs` directly,
without any higher-level application wrapper.

## How to recognize the bug

The issue is reproduced when either of the following is observed:

1. `valgrind` reports a real leak and the allocation stack points into:
   - `async_simple::coro::detail::PromiseAllocator<void, true>::operator new`
   - `coro_io::client_pool<...>::collect_idle_timeout_client(...)`
2. shutdown time tracks the configured multi-second `idle_timeout`, which shows
   that the idle collector does not observe owner destruction promptly

## Valgrind report

### Standalone reproduction

The standalone example reproduces a real leak whose allocation stack points to
`collect_idle_timeout_client()` / the internal idle collector coroutine path.

The exact byte count can vary with toolchain and build details, but the
important part is that the leaked allocation originates from:

```text
async_simple::coro::detail::PromiseAllocator<void, true>::operator new
...
coro_io::client_pool<...>::collect_idle_timeout_client(...)
```

### Integration reproduction

In my integration environment, `valgrind` reports one real leak whose allocation stack points directly to `collect_idle_timeout_client()`:

```text
4,208 (248 direct, 3,960 indirect) bytes in 1 blocks are definitely lost
  at operator new[](unsigned long, std::nothrow_t const&)
  by async_simple::coro::detail::PromiseAllocator<void, true>::operator new
  by coro_io::client_pool<...>::collect_idle_timeout_client(...)
  by coro_io::client_pool<...>::enqueue(...)
  by coro_io::client_pool<...>::collect_free_client(...)
```

So the leak is not from application-owned memory. It is the coroutine frame
allocated for the internal idle collector path.

## Observed behavior

- if the executor is force-stopped during this sleep, the coroutine frame may be leaked
- if the executor is stopped normally, shutdown may wait as long as `idle_timeout`

## Expected behavior

Destroying a `client_pool` should not:

- leak internal coroutine frames
- require waiting for the full configured `idle_timeout`

The idle collector should observe owner destruction promptly and exit naturally.

## Proposed fix

Instead of one long sleep, split `sleep_time` into small slices and re-check the weak owner after each slice.

Conceptually:

```cpp
constexpr auto kSleepSlice = std::chrono::milliseconds{50};
auto remaining = sleep_time;
while (remaining.count() > 0) {
  const auto sleep_chunk = (std::min)(remaining, kSleepSlice);
  self = nullptr;
  co_await coro_io::sleep_for(sleep_chunk);
  if ((self = self_weak.lock()) == nullptr) {
    co_return;
  }
  remaining -= sleep_chunk;
}
```

This keeps shutdown latency bounded and avoids the sleeping coroutine being stranded for the full timeout.

## Regression test suggestion

A CI-friendly regression test can assert that:

1. a client is returned to the pool
2. the idle collector enters sleep
3. the pool is destroyed
4. `io_context_pool::stop()` completes quickly, well below the full `idle_timeout`

This avoids requiring `valgrind` in CI while still catching the shutdown bug.
