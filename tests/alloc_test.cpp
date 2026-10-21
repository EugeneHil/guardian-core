// Verifies that Engine::isPotentiallyProtected never allocates. Replaces the global allocation
// functions with counting versions, so this is a plain executable (no GoogleTest).
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <utility>
#include <warden/engine.hpp>
#include <warden/policy.hpp>

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
  void* ptr = nullptr;
  std::size_t align = static_cast<std::size_t>(alignment);
  if (align < sizeof(void*)) {
    align = sizeof(void*);
  }
  if (posix_memalign(&ptr, align, size == 0 ? 1 : size) != 0) {
    throw std::bad_alloc();
  }
  return ptr;
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
void operator delete(void* ptr, std::align_val_t) noexcept { std::free(ptr); }
void operator delete[](void* ptr, std::align_val_t) noexcept { std::free(ptr); }
void operator delete(void* ptr, std::size_t, std::align_val_t) noexcept { std::free(ptr); }
void operator delete[](void* ptr, std::size_t, std::align_val_t) noexcept { std::free(ptr); }

namespace {

warden::Policy makePolicy() {
  warden::Policy policy;
  for (const char* id : {"r1", "r2"}) {
    warden::Rule rule;
    rule.id = id;
    rule.targets = {"**/.env", "~/.ssh/**", "/tmp/secrets/**"};
    warden::ProcessMatcher matcher;
    matcher.signingIdPrefix = "com.google.Chrome";
    rule.processes.push_back(matcher);
    policy.rules.push_back(std::move(rule));
  }
  return policy;
}

}  // namespace

int main() {
  const warden::Engine engine(makePolicy());
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

  return failures == 0 ? 0 : 1;
}
