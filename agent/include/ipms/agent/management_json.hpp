#pragma once

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace ipms::agent::management_json {

struct value;
using array = std::vector<value>;
using object = std::map<std::string, value>;

struct value {
  using storage_type = std::variant<std::nullptr_t, bool, std::int64_t,
                                    std::string, array, object>;
  storage_type data{nullptr};

  value() = default;
  value(std::nullptr_t) : data(nullptr) {}
  value(bool item) : data(item) {}
  template <std::floating_point T> value(T) = delete;
  template <std::integral T> requires (!std::same_as<T, bool>)
  value(T item) {
    if (!std::in_range<std::int64_t>(item))
      throw std::invalid_argument("JSON integer is outside the contract range.");
    data = static_cast<std::int64_t>(item);
  }
  value(std::string item) : data(std::move(item)) {}
  value(std::string_view item) : data(std::string(item)) {}
  value(const char* item) : data(item ? std::string(item) : std::string()) {
    if (!item) throw std::invalid_argument("JSON string pointer is null.");
  }
  value(array item) : data(std::move(item)) {}
  value(object item) : data(std::move(item)) {}

  template <typename T> T& as() { return std::get<T>(data); }
  template <typename T> const T& as() const { return std::get<T>(data); }
  template <typename T> T* get_if() { return std::get_if<T>(&data); }
  template <typename T> const T* get_if() const { return std::get_if<T>(&data); }
  bool operator==(const value&) const = default;
};

struct limits {
  std::size_t document_bytes{64 * 1024};
  std::size_t depth{8};
  // Values and object keys both count toward this bound.
  std::size_t nodes{4096};
  std::size_t string_bytes{16 * 1024};
};

// These limits may be lowered by a caller, never raised. Native snapshots use
// 48 KiB so the whole management message fits in 64 KiB. No floats are accepted.
// Strings are valid UTF-8 and may contain decoded U+0000. Typed consumers must
// reject forbidden controls/NUL before passing strings to native APIs.
value parse(std::string_view document, limits bounds = {});

// Deterministic contract JSON: sorted UTF-8 object keys, unescaped valid UTF-8,
// lowercase hex for control escapes, decimal integers, and no whitespace.
// This is not a claim of complete RFC 8785 canonicalization.
std::string serialize(const value& document, limits bounds = {});

}  // namespace ipms::agent::management_json
