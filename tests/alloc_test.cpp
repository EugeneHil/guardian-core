// Verifies that Engine::isPotentiallyProtected never allocates. Replaces the global allocation
// functions with counting versions, so this is a plain executable (no GoogleTest).
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#ifdef _MSC_VER
#include <malloc.h>
#endif
#include <new>
#include <string>
#include <utility>
#include <guardian/engine.hpp>
#include <guardian/policy.hpp>

namespace {

std::atomic<std::size_t> g_allocations{0};

void* countedAlloc(std::size_t size) {
  g_allocations.fetch_add(1, std::memory_order_relaxed);
  void* ptr = std::malloc(size == 0 ? 1 : size);
  if (ptr == nullptr) {
    throw std::bad_alloc();
  }
  return ptr;
}

void* countedAllocNoThrow(std::size_t size) noexcept {
  g_allocations.fetch_add(1, std::memory_order_relaxed);
  return std::malloc(size == 0 ? 1 : size);
}

void* countedAlignedAlloc(std::size_t size, std::align_val_t alignment) {
  g_allocations.fetch_add(1, std::memory_order_relaxed);
  std::size_t align = static_cast<std::size_t>(alignment);
  if (align < sizeof(void*)) {
    align = sizeof(void*);
  }
  const std::size_t bytes = size == 0 ? 1 : size;
#ifdef _MSC_VER
  void* ptr = _aligned_malloc(bytes, align);
  if (ptr == nullptr) {
    throw std::bad_alloc();
  }
#else
  void* ptr = nullptr;
  if (posix_memalign(&ptr, align, bytes) != 0) {
    throw std::bad_alloc();
  }
#endif
  return ptr;
}

void freeAligned(void* ptr) noexcept {
#ifdef _MSC_VER
  _aligned_free(ptr);
#else
  std::free(ptr);
#endif
}

}  // namespace

void* operator new(std::size_t size) { return countedAlloc(size); }
void* operator new[](std::size_t size) { return countedAlloc(size); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
  return countedAllocNoThrow(size);
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
  return countedAllocNoThrow(size);
}
void* operator new(std::size_t size, std::align_val_t alignment) {
  return countedAlignedAlloc(size, alignment);
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
  return countedAlignedAlloc(size, alignment);
}

void operator delete(void* ptr) noexcept { std::free(ptr); }
void operator delete[](void* ptr) noexcept { std::free(ptr); }
void operator delete(void* ptr, std::size_t) noexcept { std::free(ptr); }
void operator delete[](void* ptr, std::size_t) noexcept { std::free(ptr); }
void operator delete(void* ptr, const std::nothrow_t&) noexcept { std::free(ptr); }
void operator delete[](void* ptr, const std::nothrow_t&) noexcept { std::free(ptr); }
void operator delete(void* ptr, std::align_val_t) noexcept { freeAligned(ptr); }
void operator delete[](void* ptr, std::align_val_t) noexcept { freeAligned(ptr); }
void operator delete(void* ptr, std::size_t, std::align_val_t) noexcept { freeAligned(ptr); }
void operator delete[](void* ptr, std::size_t, std::align_val_t) noexcept { freeAligned(ptr); }

namespace {

guardian::Policy makePolicy() {
  guardian::Policy policy;
  for (const char* id : {"r1", "r2"}) {
    guardian::Rule rule;
    rule.id = id;
    rule.targets = {"**/.env", "~/.ssh/**", "/tmp/secrets/**"};
    guardian::ProcessMatcher matcher;
    matcher.signingIdPrefix = "com.google.Chrome";
    rule.processes.push_back(matcher);
    policy.rules.push_back(std::move(rule));
  }
  return policy;
}

}  // namespace

struct alignas(64) OverAligned {
  char data[64];
};

// Exercises the aligned new/delete replacements so that mismatched allocators would crash.
bool overAlignedRoundTrip() {
  const std::size_t before = g_allocations.load();
  OverAligned* single = new OverAligned();
  OverAligned* many = new OverAligned[2]();
  const bool aligned = reinterpret_cast<std::uintptr_t>(single) % 64 == 0 &&
                       reinterpret_cast<std::uintptr_t>(many) % 64 == 0;
  delete single;
  delete[] many;
  return aligned && g_allocations.load() > before;
}

int main() {
  const guardian::Engine engine(makePolicy());
  const std::string protectedPath = "/Users/alice/.ssh/id_rsa";
  const std::string unprotectedPath = "/usr/lib/libc.dylib";
  const std::string longPath = "/" + std::string(4096, 'a') + "/x";

  int failures = 0;
  const auto check = [&failures](const char* name, std::size_t before, std::size_t after,
                                 bool result, bool expected) {
    if (after != before) {
      std::fprintf(stderr, "FAIL %s: %zu allocation(s)\n", name, after - before);
      ++failures;
    }
    if (result != expected) {
      std::fprintf(stderr, "FAIL %s: unexpected result\n", name);
      ++failures;
    }
  };

  std::size_t before = g_allocations.load();
  bool result = engine.isPotentiallyProtected(protectedPath);
  check("protected", before, g_allocations.load(), result, true);

  before = g_allocations.load();
  result = engine.isPotentiallyProtected(unprotectedPath);
  check("unprotected", before, g_allocations.load(), result, false);

  before = g_allocations.load();
  result = engine.isPotentiallyProtected(longPath);
  check("long", before, g_allocations.load(), result, false);

  if (!overAlignedRoundTrip()) {
    std::fprintf(stderr, "FAIL over-aligned round trip\n");
    ++failures;
  }

  return failures == 0 ? 0 : 1;
}
