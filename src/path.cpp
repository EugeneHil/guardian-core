#include "warden/path.hpp"

#include <cstddef>
#include <vector>

namespace warden {

namespace {

bool isAlias(std::string_view segment) noexcept {
  return segment == "tmp" || segment == "var" || segment == "etc";
}

}  // namespace

std::string normalizePath(std::string_view path) {
  const bool absolute = !path.empty() && path.front() == '/';
  std::vector<std::string_view> stack;
  std::size_t pos = 0;
  while (pos <= path.size()) {
    std::size_t end = path.find('/', pos);
    if (end == std::string_view::npos) {
      end = path.size();
    }
    const std::string_view segment = std::string_view(path.data() + pos, end - pos);
    pos = end + 1;
    if (segment.empty() || segment == ".") {
      continue;
    }
    if (segment == "..") {
      if (!stack.empty() && stack.back() != "..") {
        stack.pop_back();
      } else if (!absolute) {
        stack.push_back(segment);
      }
      continue;
    }
    stack.push_back(segment);
  }

  std::string out;
  out.reserve(path.size() + 8);
  if (absolute) {
    if (stack.empty()) {
      return "/";
    }
    if (isAlias(stack.front())) {
      out += "/private";
    }
  }
  bool first = true;
  for (const std::string_view segment : stack) {
    if (absolute || !first) {
      out += '/';
    }
    out += segment;
    first = false;
  }
  return out;
}

bool isCanonicalPath(std::string_view path) noexcept {
  if (path.empty() || path.front() != '/') {
    return false;
  }
  if (path.size() == 1) {
    return true;
  }
  std::size_t pos = 1;
  bool firstSegment = true;
  while (pos <= path.size()) {
    std::size_t end = path.find('/', pos);
    if (end == std::string_view::npos) {
      end = path.size();
    }
    const std::string_view segment = std::string_view(path.data() + pos, end - pos);
    if (segment.empty() || segment == "." || segment == "..") {
      return false;
    }
    if (firstSegment && isAlias(segment)) {
      return false;
    }
    firstSegment = false;
    pos = end + 1;
  }
  return true;
}

std::string expandTarget(std::string_view target) {
  constexpr std::string_view kHome = "/Users/*";
  if (target == "~") {
    return std::string(kHome);
  }
  if (target.size() > 1 && target[0] == '~' && target[1] == '/') {
    std::string out(kHome);
    out += target.substr(1);
    return out;
  }
  return std::string(target);
}

}  // namespace warden
