#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>
#include <warden/glob.hpp>
#include <warden/path.hpp>
#include <warden/policy_parser.hpp>

namespace warden {

namespace {

using Json = nlohmann::json;

constexpr std::size_t kMaxNesting = 64;

/// Cheap pre-scan so hostile input cannot build (or later destroy) a deeply nested value.
bool exceedsNesting(std::string_view text) noexcept {
  std::size_t depth = 0;
  bool inString = false;
  bool escaped = false;
  for (const char c : text) {
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else if (c == '"') {
        inString = false;
      }
    } else if (c == '"') {
      inString = true;
    } else if (c == '[' || c == '{') {
      if (++depth > kMaxNesting) {
        return true;
      }
    } else if ((c == ']' || c == '}') && depth > 0) {
      --depth;
    }
  }
  return false;
}

std::string childPath(const std::string& parent, const std::string& name) {
  return parent.empty() ? name : parent + "." + name;
}

std::string indexPath(const std::string& parent, std::size_t index) {
  return parent + "[" + std::to_string(index) + "]";
}

/// Accumulates errors. The empty path denotes the document root.
class Collector {
 public:
  void add(const std::string& path, std::string message) {
    errors_.push_back(ValidationError{path.empty() ? "$" : path, std::move(message)});
  }

  /// Unknown keys of the root object are reported at the key itself, deeper ones at the object.
  void rejectUnknown(const Json& object, const std::string& path,
                     std::initializer_list<const char*> known) {
    for (const auto& item : object.items()) {
      bool isKnown = false;
      for (const char* name : known) {
        if (item.key() == name) {
          isKnown = true;
          break;
        }
      }
      if (!isKnown) {
        add(path.empty() ? item.key() : path, "unknown field '" + item.key() + "'");
      }
    }
  }

  bool expectObject(const Json& value, const std::string& path) {
    if (!value.is_object()) {
      add(path, "expected object");
      return false;
    }
    return true;
  }

  bool readString(const Json& value, const std::string& path, std::string& out) {
    if (!value.is_string()) {
      add(path, "expected string");
      return false;
    }
    out = value.get<std::string>();
    return true;
  }

  /// Integers only: floats (even 3.0) and unsigned values above int64 max are rejected.
  bool readInteger(const Json& value, const std::string& path, std::int64_t& out) {
    if (value.is_number_integer()) {
      if (value.is_number_unsigned() &&
          value.get<std::uint64_t>() >
              static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        add(path, "expected integer");
        return false;
      }
      out = value.get<std::int64_t>();
      return true;
    }
    add(path, "expected integer");
    return false;
  }

  /// Returns the field, or nullptr after recording "missing".
  const Json* required(const Json& object, const std::string& name, const std::string& path) {
    const auto found = object.find(name);
    if (found == object.end()) {
      add(childPath(path, name), "missing");
      return nullptr;
    }
    return &*found;
  }

  void parseMatcher(const Json& value, const std::string& path, ProcessMatcher& out) {
    if (!expectObject(value, path)) {
      return;
    }
    rejectUnknown(value, path, {"teamId", "signingId", "signingIdPrefix", "path"});
    const auto readOptional = [&](const char* name, std::optional<std::string>& field) {
      const auto found = value.find(name);
      if (found == value.end()) {
        return;
      }
      std::string text;
      if (readString(*found, childPath(path, name), text)) {
        if (text.empty()) {
          add(childPath(path, name), "empty value");
        }
        field = std::move(text);
      }
    };
    readOptional("teamId", out.teamId);
    readOptional("signingId", out.signingId);
    readOptional("signingIdPrefix", out.signingIdPrefix);
    readOptional("path", out.path);
    if (!out.teamId && !out.signingId && !out.signingIdPrefix && !out.path &&
        !hasKnownField(value)) {
      add(path, "empty matcher");
    }
    if (out.path && !out.path->empty() && out.path->front() != '/') {
      add(childPath(path, "path"), "must be absolute");
    } else if (out.path && !out.path->empty() && !isCanonicalPath(*out.path)) {
      add(childPath(path, "path"),
          "must be canonical (no '.', '..', '//', trailing '/', or /tmp, /var, /etc alias "
          "prefix)");
    }
  }

  static bool hasKnownField(const Json& object) {
    return object.contains("teamId") || object.contains("signingId") ||
           object.contains("signingIdPrefix") || object.contains("path");
  }

  void parseTargets(const Json& value, const std::string& path, Rule& out) {
    const Json* targets = required(value, "targets", path);
    if (targets == nullptr) {
      return;
    }
    const std::string targetsPath = childPath(path, "targets");
    if (!targets->is_array()) {
      add(targetsPath, "expected array");
      return;
    }
    if (targets->empty()) {
      add(targetsPath, "no targets");
    }
    for (std::size_t i = 0; i < targets->size(); ++i) {
      std::string target;
      if (readString((*targets)[i], indexPath(targetsPath, i), target)) {
        if (const std::optional<std::string> problem = globError(target)) {
          add(indexPath(targetsPath, i), *problem);
        }
        out.targets.push_back(std::move(target));
      }
    }
  }

  void parseAction(const Json& value, const std::string& path, Rule& out) {
    const Json* action = required(value, "action", path);
    if (action == nullptr) {
      return;
    }
    const std::string actionPath = childPath(path, "action");
    std::string text;
    if (!readString(*action, actionPath, text)) {
      return;
    }
    if (text == "deny") {
      out.action = Action::Deny;
    } else {
      add(actionPath, "unsupported action '" + text + "' (expected 'deny')");
    }
  }

  void parseProcesses(const Json& value, const std::string& path, Rule& out) {
    const Json* processes = required(value, "processes", path);
    if (processes == nullptr) {
      return;
    }
    const std::string processesPath = childPath(path, "processes");
    if (!processes->is_array()) {
      add(processesPath, "expected array");
      return;
    }
    if (processes->empty()) {
      add(processesPath, "no processes");
    }
    for (std::size_t i = 0; i < processes->size(); ++i) {
      ProcessMatcher matcher;
      parseMatcher((*processes)[i], indexPath(processesPath, i), matcher);
      out.processes.push_back(std::move(matcher));
    }
  }

  void checkId(const std::string& id, const std::string& path) {
    if (id.empty()) {
      add(path, "empty id");
    } else if (!seenIds_.insert(id).second) {
      add(path, "duplicate id '" + id + "'");
    }
  }

  void parseRule(const Json& value, const std::string& path, Rule& out) {
    if (!expectObject(value, path)) {
      return;
    }
    rejectUnknown(value, path, {"id", "description", "targets", "action", "processes"});

    const Json* id = required(value, "id", path);
    if (id != nullptr && readString(*id, childPath(path, "id"), out.id)) {
      checkId(out.id, childPath(path, "id"));
    }
    if (const auto found = value.find("description"); found != value.end()) {
      readString(*found, childPath(path, "description"), out.description);
    }
    parseTargets(value, path, out);
    parseAction(value, path, out);
    parseProcesses(value, path, out);
  }

  Policy parseRoot(const Json& root) {
    Policy policy;
    if (!expectObject(root, "")) {
      return policy;
    }
    rejectUnknown(root, "", {"schemaVersion", "version", "rules"});

    if (const Json* schema = required(root, "schemaVersion", "")) {
      std::int64_t number = 0;
      if (readInteger(*schema, "schemaVersion", number)) {
        if (number < std::numeric_limits<int>::min() || number > std::numeric_limits<int>::max()) {
          add("schemaVersion", "expected integer");
        } else {
          policy.schemaVersion = static_cast<int>(number);
          if (number != 1) {
            add("schemaVersion",
                "unsupported schema version " + std::to_string(number) + " (expected 1)");
          }
        }
      }
    }
    const Json* version = required(root, "version", "");
    if (version != nullptr && readInteger(*version, "version", policy.version) &&
        policy.version < 0) {
      add("version", "must be >= 0");
    }
    if (const Json* rules = required(root, "rules", "")) {
      if (!rules->is_array()) {
        add("rules", "expected array");
      } else {
        for (std::size_t i = 0; i < rules->size(); ++i) {
          Rule rule;
          parseRule((*rules)[i], indexPath("rules", i), rule);
          policy.rules.push_back(std::move(rule));
        }
      }
    }
    return policy;
  }

  std::vector<ValidationError> take() { return std::move(errors_); }
  [[nodiscard]] bool empty() const noexcept { return errors_.empty(); }

 private:
  std::vector<ValidationError> errors_;
  std::unordered_set<std::string> seenIds_;
};

ParseResult failure(std::string message) {
  ParseResult result;
  result.errors.push_back(ValidationError{"$", std::move(message)});
  return result;
}

}  // namespace

ParseResult parsePolicy(std::string_view json) {
  if (exceedsNesting(json)) {
    return failure("nesting too deep");
  }
  Json root;
  try {
    root = Json::parse(json.begin(), json.end(), nullptr, true, false);
  } catch (const Json::exception& error) {
    return failure(std::string("invalid JSON: ") + error.what());
  }

  Collector collector;
  Policy policy = collector.parseRoot(root);
  ParseResult result;
  if (collector.empty()) {
    result.policy = std::move(policy);
  } else {
    result.errors = collector.take();
  }
  return result;
}

std::string describe(const ValidationError& error) { return error.path + ": " + error.message; }

}  // namespace warden
