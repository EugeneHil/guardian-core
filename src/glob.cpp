#include "warden/glob.hpp"

#include <cstddef>

namespace warden {

namespace {

// Iterates the `/`-separated segments of a string. An empty string has zero segments;
// "a/" has two ("a" and "").
struct Cursor {
  std::string_view rest;
  bool done;

  explicit Cursor(std::string_view s) noexcept : rest(s), done(s.empty()) {}

  [[nodiscard]] std::string_view peek() const noexcept {
    const std::size_t slash = rest.find('/');
    return {rest.data(), slash == std::string_view::npos ? rest.size() : slash};
  }

  void advance() noexcept {
    const std::size_t slash = rest.find('/');
    if (slash == std::string_view::npos) {
      rest = std::string_view();
      done = true;
    } else {
      rest.remove_prefix(slash + 1);
    }
  }
};

// Segment-level wildcard match: `*` matches any run of characters (segments contain no `/`).
bool segmentMatch(std::string_view pat, std::string_view seg) noexcept {
  std::size_t p = 0;
  std::size_t s = 0;
  std::size_t starP = std::string_view::npos;
  std::size_t starS = 0;
  while (s < seg.size()) {
    if (p < pat.size() && pat[p] == '*') {
      starP = ++p;
      starS = s;
    } else if (p < pat.size() && pat[p] == seg[s]) {
      ++p;
      ++s;
    } else if (starP != std::string_view::npos) {
      p = starP;
      s = ++starS;
    } else {
      return false;
    }
  }
  while (p < pat.size() && pat[p] == '*') {
    ++p;
  }
  return p == pat.size();
}

}  // namespace

bool globMatch(std::string_view pattern, std::string_view path) noexcept {
  if (!pattern.empty() && pattern.front() == '/') {
    if (path.empty() || path.front() != '/') {
      return false;
    }
    pattern.remove_prefix(1);
  }
  if (!path.empty() && path.front() == '/') {
    path.remove_prefix(1);
  }
  Cursor p(pattern);
  Cursor s(path);
  bool hasStar = false;
  Cursor starP{std::string_view()};
  Cursor starS{std::string_view()};
  while (!s.done) {
    if (!p.done) {
      const std::string_view ps = p.peek();
      if (ps == "**") {
        p.advance();
        hasStar = true;
        starP = p;
        starS = s;
        continue;
      }
      if (segmentMatch(ps, s.peek())) {
        p.advance();
        s.advance();
        continue;
      }
    }
    if (!hasStar) {
      return false;
    }
    starS.advance();
    s = starS;
    p = starP;
  }
  while (!p.done && p.peek() == "**") {
    p.advance();
  }
  return p.done;
}

std::optional<std::string> globError(std::string_view target) {
  if (target.empty()) {
    return "empty target";
  }
  if (target.front() == '~') {
    target.remove_prefix(1);
    if (!target.empty() && target.front() != '/') {
      return "'~' must be followed by '/' or end";
    }
    if (target.empty()) {
      return std::nullopt;
    }
  } else if (target.front() != '/' && target.substr(0, 2) != "**") {
    return "target must start with '/', '~' or '**'";
  }
  if (target.back() == '/') {
    return "trailing '/'";
  }
  if (target.front() == '/') {
    target.remove_prefix(1);
  }
  Cursor c(target);
  while (!c.done) {
    const std::string_view seg = c.peek();
    if (seg.empty()) {
      return "empty path segment";
    }
    if (seg == "." || seg == "..") {
      return "'.' and '..' segments are not allowed";
    }
    if (seg != "**" && seg.find("**") != std::string_view::npos) {
      return "'**' must be a whole segment";
    }
    c.advance();
  }
  return std::nullopt;
}

}  // namespace warden
