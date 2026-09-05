#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ipms::agent {

inline bool native_console_uuid(std::string_view value) {
  if (value.size() != 36) return false;
  for (std::size_t index = 0; index < value.size(); ++index) {
    const char c = value[index];
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (c != '-') return false;
    } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F'))) return false;
  }
  return true;
}

// Bound the complete WebSocket message, not just each API receive buffer.
class native_console_message {
 public:
  enum class status { pending, complete, rejected };
  status append(std::span<const std::uint8_t> bytes, bool text, bool final) {
    if (state_ != status::pending || (started_ && text_ != text) ||
        bytes.size() > (text ? 256u : 65'536u) - data_.size()) {
      state_ = status::rejected;
      return state_;
    }
    started_ = true;
    text_ = text;
    data_.insert(data_.end(), bytes.begin(), bytes.end());
    if (final) state_ = status::complete;
    return state_;
  }
  void reset() { data_.clear(); started_ = false; state_ = status::pending; }
  std::span<const std::uint8_t> bytes() const { return data_; }
 private:
  std::vector<std::uint8_t> data_;
  bool text_{false}, started_{false};
  status state_{status::pending};
};

// One-shot preconnection gate. Nothing is forwarded until the entire PDU has
// passed. Bytes after the PDU belong to the caller, never to this small buffer.
class native_preconnection_guard {
 public:
  enum class status { pending, accepted, rejected };
  struct result { status state; std::size_t consumed; };

  explicit native_preconnection_guard(std::string_view vm_id) : vm_id_(vm_id) {
    if (!native_console_uuid(vm_id)) state_ = status::rejected;
  }

  result append(std::span<const std::uint8_t> input) {
    if (state_ != status::pending) {
      state_ = status::rejected;
      return {state_, 0};
    }
    std::size_t consumed = 0;
    while (consumed < input.size() && size_ < expected_) {
      buffer_[size_++] = input[consumed++];
      if (size_ == 4) {
        expected_ = u32(0);
        if (expected_ < 20 || expected_ > buffer_.size() || expected_ % 2 != 0) {
          state_ = status::rejected;
          return {state_, consumed};
        }
      }
    }
    if (size_ == expected_) state_ = validate() ? status::accepted : status::rejected;
    return {state_, consumed};
  }

  std::span<const std::uint8_t> packet() const {
    return state_ == status::accepted ? std::span(buffer_).first(size_) :
                                      std::span<const std::uint8_t>{};
  }

 private:
  std::uint32_t u32(std::size_t at) const {
    return static_cast<std::uint32_t>(buffer_[at]) |
        (static_cast<std::uint32_t>(buffer_[at + 1]) << 8) |
        (static_cast<std::uint32_t>(buffer_[at + 2]) << 16) |
        (static_cast<std::uint32_t>(buffer_[at + 3]) << 24);
  }
  bool validate() const {
    // RDP_PRECONNECTION_PDU_V2: flags and the unused numerical identifier
    // are deliberately fixed at zero for this compiled-in basic-console path.
    if (size_ < 20 || u32(4) != 0 || u32(8) != 2 || u32(12) != 0) return false;
    const auto count = static_cast<std::size_t>(buffer_[16]) |
        (static_cast<std::size_t>(buffer_[17]) << 8);
    if (count == 0 || size_ != 18 + count * 2 ||
        buffer_[size_ - 2] != 0 || buffer_[size_ - 1] != 0) return false;
    std::string pcb;
    for (std::size_t index = 18; index + 2 < size_; index += 2) {
      if (buffer_[index] == 0 || buffer_[index] > 127 || buffer_[index + 1] != 0)
        return false;
      pcb.push_back(static_cast<char>(buffer_[index]));
    }
    constexpr std::string_view suffix = ";EnhancedMode=0";
    if (pcb.size() != 36 && (pcb.size() != 36 + suffix.size() ||
                             pcb.substr(36) != suffix)) return false;
    if (!native_console_uuid(std::string_view(pcb).substr(0, 36))) return false;
    const auto lower = [](char c) { return c >= 'A' && c <= 'F' ? c + ('a' - 'A') : c; };
    for (std::size_t index = 0; index < 36; ++index)
      if (lower(pcb[index]) != lower(vm_id_[index])) return false;
    return true;
  }
  std::string vm_id_;
  std::array<std::uint8_t, 256> buffer_{};
  std::size_t size_{0};
  std::size_t expected_{4};
  status state_{status::pending};
};

// This intentionally accepts only the three lease fields, without duplicate
// keys, escapes, extra data or coercion. It is not a general JSON interpreter.
inline std::optional<int> native_lease_seconds(std::string_view json,
                                              std::string_view generation) {
  if (json.size() > 256 || !native_console_uuid(generation)) return std::nullopt;
  std::size_t cursor = 0;
  const auto whitespace = [&] {
    while (cursor < json.size() && (json[cursor] == ' ' || json[cursor] == '\t' ||
                                   json[cursor] == '\r' || json[cursor] == '\n')) ++cursor;
  };
  const auto token = [&](char value) {
    whitespace();
    if (cursor == json.size() || json[cursor] != value) return false;
    ++cursor;
    return true;
  };
  const auto string = [&]() -> std::optional<std::string_view> {
    if (!token('"')) return std::nullopt;
    const auto start = cursor;
    while (cursor < json.size() && json[cursor] != '"') {
      if (json[cursor] < 32 || json[cursor] == '\\') return std::nullopt;
      ++cursor;
    }
    if (cursor == json.size()) return std::nullopt;
    return json.substr(start, cursor++ - start);
  };
  if (!token('{')) return std::nullopt;
  unsigned fields = 0;
  int seconds = 0;
  for (int index = 0; index < 3; ++index) {
    const auto key = string();
    if (!key || !token(':')) return std::nullopt;
    if (*key == "type" || *key == "stream_generation") {
      const unsigned bit = *key == "type" ? 1 : 2;
      if (fields & bit) return std::nullopt;
      fields |= bit;
      const auto value = string();
      if (!value || *value != (*key == "type" ? std::string_view("lease") : generation))
        return std::nullopt;
    } else if (*key == "seconds") {
      if (fields & 4) return std::nullopt;
      fields |= 4;
      whitespace();
      const auto start = cursor;
      while (cursor < json.size() && json[cursor] >= '0' && json[cursor] <= '9') {
        if (cursor - start >= 2) return std::nullopt;
        seconds = seconds * 10 + json[cursor++] - '0';
      }
      if (cursor == start || json[start] == '0' || seconds > 15) return std::nullopt;
    } else return std::nullopt;
    if (!token(index < 2 ? ',' : '}')) return std::nullopt;
  }
  whitespace();
  if (cursor != json.size() || fields != 7 || seconds < 1) return std::nullopt;
  return seconds;
}

class native_console_lease {
 public:
  using clock = std::chrono::steady_clock;
  native_console_lease(std::string generation, clock::time_point now)
      : generation_(std::move(generation)), last_(now), deadline_(now + std::chrono::seconds(15)) {}
  bool refresh(std::string_view control, clock::time_point now) {
    const auto seconds = native_lease_seconds(control, generation_);
    if (!seconds || now < last_ || now >= deadline_ || failed_) {
      failed_ = true;
      return false;
    }
    received_ = true;
    last_ = now;
    deadline_ = now + std::chrono::seconds(*seconds);
    return true;
  }
  bool live(clock::time_point now) const {
    return !failed_ && now >= last_ && now < deadline_;
  }
  bool authorized(clock::time_point now) const { return received_ && live(now); }
 private:
  std::string generation_;
  clock::time_point last_, deadline_;
  bool received_{false};
  bool failed_{false};
};

}  // namespace ipms::agent
