# PR: fix `coro_io::client_pool` idle collector shutdown leak / long stop latency

## Summary

This PR fixes a shutdown lifecycle issue in `coro_io::client_pool`.

Before this change, the internal idle collector coroutine
`collect_idle_timeout_client()` slept for the whole `idle_timeout` in one
`co_await coro_io::sleep_for(sleep_time)`.

If the owning `client_pool` was destroyed during that sleep:

- force-stopping the executor could strand the coroutine frame and show up as a leak
- normal stop could block until the full `idle_timeout` expired

## Root cause

The idle collector only checked whether the owner still existed after the full
sleep finished:

```cpp
clients.reselect();
self = nullptr;
co_await coro_io::sleep_for(sleep_time);
if ((self = self_weak.lock()) == nullptr) {
  break;
}
```

That makes shutdown responsiveness depend directly on `idle_timeout`.

## Fix

Split the sleep interval into short slices and re-check the weak owner after
each slice:

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

This keeps stop latency bounded and lets the coroutine exit naturally once the
pool is gone.

## Changes

### Code

- `include/ylt/coro_io/client_pool.hpp`
  - make `collect_idle_timeout_client()` sleep in short slices
  - exit immediately once `self_weak` can no longer be locked

### Tests

- `src/coro_io/tests/test_client_pool.cpp`
  - add regression test:
    - `test client pool shutdown latency during idle collection`

The new test verifies that destroying a pool while the idle collector is
sleeping does not make `io_context_pool::stop()` wait for the full multi-second
idle timeout.

## Why this belongs in the library

This is not cleanly solvable in upper-layer code because the problematic
coroutine is created and owned internally by `client_pool`.

Application code should not need to know:

- whether an idle collector is running
- how long it is sleeping
- how long it must wait before destruction
- whether force stop is required to avoid long shutdown

That responsibility belongs inside the library.

## Reproduction context

The bug is now confirmed in two places:

1. a standalone reproducer inside `yalantinglibs`
2. an integration binary using `coro_io::client_pool` indirectly through a
   higher-level SDK

For the standalone reproducer on WSL, build with:

```bash
rm -rf build-wsl
cmake -S . -B build-wsl -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZER=OFF
cmake --build build-wsl --target coro_io_example_idle_collector_shutdown_repro -j
valgrind --leak-check=full --show-leak-kinds=all \
  ./build-wsl/output/examples/coro_io_example_idle_collector_shutdown_repro
```

The exact leak byte count can vary by toolchain, but the important allocation
stack points into the internal idle collector coroutine path, i.e.
`PromiseAllocator<void, true>::operator new` ->
`collect_idle_timeout_client(...)`.

In the integration binary, `valgrind` reported:

```text
4,208 (248 direct, 3,960 indirect) bytes in 1 blocks are definitely lost
  by coro_io::client_pool<...>::collect_idle_timeout_client(...)
```

After applying this fix in the integration environment, the same program
reported:

```text
HEAP SUMMARY:
    in use at exit: 0 bytes in 0 blocks
    total heap usage: 16,102 allocs, 16,102 frees, 2,601,743 bytes allocated

All heap blocks were freed -- no leaks are possible

ERROR SUMMARY: 0 errors from 0 contexts
```

For WSL reproduction with `valgrind`, the example must be built with
`-DENABLE_SANITIZER=OFF`. A Debug build with the default
`ENABLE_SANITIZER=ON` links ASan and produces invalid `valgrind` output such as:

```text
ASan runtime does not come first in initial library list
total heap usage: 0 allocs, 0 frees, 0 bytes allocated
```

## Local verification

Built and ran the new regression test locally:

```text
[doctest] test cases: 1 | 1 passed | 0 failed | 40 skipped
[doctest] assertions: 4 | 4 passed | 0 failed
[doctest] Status: SUCCESS!
```

## Notes

This PR intentionally keeps the fix minimal and scoped to `client_pool`
shutdown behavior. It does not change higher-level application cleanup logic.
