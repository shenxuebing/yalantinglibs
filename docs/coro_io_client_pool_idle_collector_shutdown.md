# coro_io `client_pool` idle collector shutdown leak

## Summary

`coro_io::client_pool` starts a background coroutine named
`collect_idle_timeout_client()` after a free client is returned to the pool.
Before this fix, the coroutine slept for the full `idle_timeout` interval in one
`co_await coro_io::sleep_for(sleep_time)`.

If the owning `client_pool` was destroyed while that coroutine was sleeping,
applications typically had two bad choices:

1. call `io_context_pool::stop(true)` and leak the sleeping coroutine frame, or
2. call `io_context_pool::stop()` and block until the full idle timeout expired.

This is a library bug in the idle collector shutdown path.

## Impact

- `valgrind` reports one real leak from `collect_idle_timeout_client()`
- shutdown latency can be as large as `idle_timeout`
- upper-layer code cannot fix this cleanly without knowing `client_pool`
  internals

## Root cause

The idle collector used a single long sleep:

```cpp
clients.reselect();
self = nullptr;
co_await coro_io::sleep_for(sleep_time);
if ((self = self_weak.lock()) == nullptr) {
  break;
}
```

That means the coroutine does not observe pool destruction until the sleep
finishes. If the underlying executor is force-stopped during that sleep, the
coroutine frame allocated by `async_simple::coro::Lazy<void>` may never get a
normal completion path.

## Fix

Split the idle wait into short slices and re-check the weak owner after each
slice:

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

This keeps shutdown latency bounded and allows normal `io_context_pool::stop()`
to drain the coroutine naturally.

## Minimal reproduction

The following standalone example reproduces the bug without any application
wrapper logic:

```cpp
#include <async_simple/coro/SyncAwait.h>
#include <ylt/coro_io/client_pool.hpp>
#include <ylt/coro_io/coro_io.hpp>
#include <ylt/coro_rpc/impl/coro_rpc_client.hpp>
#include <ylt/coro_rpc/impl/coro_rpc_server.hpp>

using namespace std::chrono_literals;

int main() {
  coro_rpc::coro_rpc_server server(1, 8801);
  auto started = server.async_start();

  auto io_pool = std::make_shared<coro_io::io_context_pool>(1);
  std::thread runner([io_pool] { io_pool->run(); });

  auto pool = coro_io::client_pool<coro_rpc::coro_rpc_client>::create(
      "127.0.0.1:8801",
      {.max_connection = 1, .idle_timeout = 3s, .short_connect_idle_timeout = 3s},
      *io_pool);

  async_simple::coro::syncAwait([&]() -> async_simple::coro::Lazy<void> {
    auto ret = co_await pool->send_request(
        [](coro_rpc::coro_rpc_client&) -> async_simple::coro::Lazy<void> {
          co_return;
        });
    co_await coro_io::sleep_for(20ms); // let the idle collector start sleeping
  }());

  pool.reset();
  io_pool->stop();
  runner.join();
  server.stop();
}
```

When reproducing under WSL with `valgrind`, configure with
`-DENABLE_SANITIZER=OFF`. The default Debug configuration enables ASan, and
that makes the `valgrind` result unusable for this issue.

## Reproduction report

This issue was first observed in an integration binary that uses
`coro_io::client_pool` through a higher-level SDK. The important part of the
`valgrind` output is the allocation stack, which points directly to
`collect_idle_timeout_client()`:

```text
4,208 (248 direct, 3,960 indirect) bytes in 1 blocks are definitely lost
  at operator new[](unsigned long, std::nothrow_t const&)
  by async_simple::coro::detail::PromiseAllocator<void, true>::operator new
  by coro_io::client_pool<...>::collect_idle_timeout_client(...)
  by coro_io::client_pool<...>::enqueue(...)
  by coro_io::client_pool<...>::collect_free_client(...)
```

After the fix, the same binary reports:

```text
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
    total heap usage: 16,102 allocs, 16,102 frees, 2,601,743 bytes allocated

All heap blocks were freed -- no leaks are possible

ERROR SUMMARY: 0 errors from 0 contexts
```

## Regression coverage

A CI-friendly regression test was added in:

- `src/coro_io/tests/test_client_pool.cpp`

It does not depend on `valgrind`. Instead, it asserts that destroying a pool
while its idle collector is sleeping does not make `io_context_pool::stop()`
wait for the full multi-second idle timeout.
