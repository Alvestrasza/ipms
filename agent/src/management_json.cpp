#include "ipms/agent/management_json.hpp"

#include <charconv>
#include <system_error>

namespace ipms::agent::management_json {
namespace {
[[noreturn]] void invalid() {
  // Do not include untrusted document contents in errors or operational logs.
  throw std::invalid_argument("Invalid or over-limit management JSON.");
}

void validate_limits(const limits& bounds) {
  constexpr limits maximum{};
  if (bounds.document_bytes == 0 || bounds.document_bytes > maximum.document_bytes ||
      bounds.depth > maximum.depth || bounds.nodes == 0 || bounds.nodes > maximum.nodes ||
      bounds.string_bytes > maximum.string_bytes) invalid();
}

// Returns the width of one shortest-form UTF-8 scalar, excluding surrogate
// codepoints and values beyond U+10FFFF. ASCII NUL is a valid scalar here.
std::size_t utf8_width(std::string_view text, std::size_t offset) {
  if (offset >= text.size()) invalid();
  const auto first = static_cast<unsigned char>(text[offset]);
  if (first < 0x80) return 1;
  std::size_t width{};
  std::uint32_t point{};
  std::uint32_t minimum{};
  if (first >= 0xc2 && first <= 0xdf) { width = 2; point = first & 0x1f; minimum = 0x80; }
  else if (first >= 0xe0 && first <= 0xef) { width = 3; point = first & 0x0f; minimum = 0x800; }
  else if (first >= 0xf0 && first <= 0xf4) { width = 4; point = first & 0x07; minimum = 0x10000; }
  else invalid();
  if (text.size() - offset < width) invalid();
  for (std::size_t index = 1; index < width; ++index) {
    const auto next = static_cast<unsigned char>(text[offset + index]);
    if ((next & 0xc0) != 0x80) invalid();
    point = (point << 6) | (next & 0x3f);
  }
  if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) invalid();
  return width;
}

class parser {
 public:
  parser(std::string_view source, limits bounds) : source_(source), bounds_(bounds) {
    validate_limits(bounds_);
    if (source_.size() > bounds_.document_bytes) invalid();
  }

  value run() {
    whitespace();
    auto document = read_value(0);
    whitespace();
    if (position_ != source_.size()) invalid();
    return document;
  }

 private:
  std::string_view source_;
  limits bounds_;
  std::size_t position_{};
  std::size_t nodes_{};

  void node() { if (++nodes_ > bounds_.nodes) invalid(); }
  char peek() const { return position_ < source_.size() ? source_[position_] : '\0'; }
  bool consume(char item) {
    if (position_ >= source_.size() || source_[position_] != item) return false;
    ++position_;
    return true;
  }
  void whitespace() {
    while (position_ < source_.size() &&
           (source_[position_] == ' ' || source_[position_] == '\t' ||
            source_[position_] == '\r' || source_[position_] == '\n')) ++position_;
  }
  void literal(std::string_view text) {
    if (source_.substr(position_, text.size()) != text) invalid();
    position_ += text.size();
  }
  std::uint32_t hex4() {
    if (source_.size() - position_ < 4) invalid();
    std::uint32_t point{};
    for (int index = 0; index < 4; ++index) {
      const char next = source_[position_++];
      std::uint32_t digit{};
      if (next >= '0' && next <= '9') digit = static_cast<std::uint32_t>(next - '0');
      else if (next >= 'a' && next <= 'f') digit = static_cast<std::uint32_t>(next - 'a' + 10);
      else if (next >= 'A' && next <= 'F') digit = static_cast<std::uint32_t>(next - 'A' + 10);
      else invalid();
      point = (point << 4) | digit;
    }
    return point;
  }
  void append_scalar(std::string& output, std::uint32_t point) {
    if (point <= 0x7f) output.push_back(static_cast<char>(point));
    else if (point <= 0x7ff) {
      output.push_back(static_cast<char>(0xc0 | (point >> 6)));
      output.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    } else if (point <= 0xffff) {
      output.push_back(static_cast<char>(0xe0 | (point >> 12)));
      output.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    } else {
      output.push_back(static_cast<char>(0xf0 | (point >> 18)));
      output.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
      output.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    }
  }
  std::string read_string() {
    if (!consume('"')) invalid();
    std::string output;
    while (position_ < source_.size()) {
      const auto next = static_cast<unsigned char>(source_[position_]);
      if (next == '"') { ++position_; return output; }
      if (next < 0x20) invalid();
      if (next != '\\') {
        const auto width = utf8_width(source_, position_);
        output.append(source_.substr(position_, width));
        position_ += width;
      } else {
        ++position_;
        if (position_ >= source_.size()) invalid();
        switch (source_[position_++]) {
          case '"': output.push_back('"'); break;
          case '\\': output.push_back('\\'); break;
          case '/': output.push_back('/'); break;
          case 'b': output.push_back('\b'); break;
          case 'f': output.push_back('\f'); break;
          case 'n': output.push_back('\n'); break;
          case 'r': output.push_back('\r'); break;
          case 't': output.push_back('\t'); break;
          case 'u': {
            auto point = hex4();
            if (point >= 0xd800 && point <= 0xdbff) {
              if (!consume('\\') || !consume('u')) invalid();
              const auto low = hex4();
              if (low < 0xdc00 || low > 0xdfff) invalid();
              point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
            } else if (point >= 0xdc00 && point <= 0xdfff) invalid();
            append_scalar(output, point);
            break;
          }
          default: invalid();
        }
      }
      if (output.size() > bounds_.string_bytes) invalid();
    }
    invalid();
  }
  value integer() {
    const auto start = position_;
    (void)consume('-');
    if (consume('0')) {
      if (peek() >= '0' && peek() <= '9') invalid();
    } else {
      if (peek() < '1' || peek() > '9') invalid();
      do { ++position_; } while (peek() >= '0' && peek() <= '9');
    }
    if (peek() == '.' || peek() == 'e' || peek() == 'E') invalid();
    std::int64_t result{};
    const auto [end, error] = std::from_chars(source_.data() + start,
                                             source_.data() + position_, result);
    if (error != std::errc{} || end != source_.data() + position_) invalid();
    return result;
  }
  value read_value(std::size_t depth) {
    node();
    switch (peek()) {
      case 'n': literal("null"); return nullptr;
      case 't': literal("true"); return true;
      case 'f': literal("false"); return false;
      case '"': return read_string();
      case '[': {
        if (depth >= bounds_.depth) invalid();
        ++position_;
        whitespace();
        array result;
        if (consume(']')) return result;
        do {
          whitespace();
          result.push_back(read_value(depth + 1));
          whitespace();
          if (consume(']')) return result;
        } while (consume(','));
        invalid();
      }
      case '{': {
        if (depth >= bounds_.depth) invalid();
        ++position_;
        whitespace();
        object result;
        if (consume('}')) return result;
        do {
          whitespace();
          node();
          auto key = read_string();
          if (result.contains(key)) invalid();
          whitespace();
          if (!consume(':')) invalid();
          whitespace();
          auto item = read_value(depth + 1);
          result.emplace(std::move(key), std::move(item));
          whitespace();
          if (consume('}')) return result;
        } while (consume(','));
        invalid();
      }
      default: return integer();
    }
  }
};

class serializer {
 public:
  explicit serializer(limits bounds) : bounds_(bounds) { validate_limits(bounds_); }
  std::string run(const value& document) {
    write_value(document, 0);
    return std::move(output_);
  }

 private:
  limits bounds_;
  std::string output_;
  std::size_t nodes_{};
  void node() { if (++nodes_ > bounds_.nodes) invalid(); }
  void append(std::string_view text) {
    if (text.size() > bounds_.document_bytes - output_.size()) invalid();
    output_.append(text);
  }
  void character(char text) { append(std::string_view(&text, 1)); }
  void string(std::string_view text) {
    if (text.size() > bounds_.string_bytes) invalid();
    character('"');
    for (std::size_t index = 0; index < text.size();) {
      const auto next = static_cast<unsigned char>(text[index]);
      switch (next) {
        case '"': append("\\\""); break;
        case '\\': append("\\\\"); break;
        case '\b': append("\\b"); break;
        case '\f': append("\\f"); break;
        case '\n': append("\\n"); break;
        case '\r': append("\\r"); break;
        case '\t': append("\\t"); break;
        default: {
          if (next < 0x20) {
            constexpr std::string_view hex = "0123456789abcdef";
            append("\\u00");
            character(hex[next >> 4]);
            character(hex[next & 0x0f]);
          } else {
            const auto width = utf8_width(text, index);
            append(text.substr(index, width));
            index += width;
            continue;
          }
        }
      }
      ++index;
    }
    character('"');
  }
  void write_value(const value& document, std::size_t depth) {
    node();
    std::visit([&](const auto& item) {
      using T = std::decay_t<decltype(item)>;
      if constexpr (std::same_as<T, std::nullptr_t>) append("null");
      else if constexpr (std::same_as<T, bool>) append(item ? "true" : "false");
      else if constexpr (std::same_as<T, std::int64_t>) {
        char buffer[32]{};
        const auto [end, error] = std::to_chars(buffer, buffer + sizeof(buffer), item);
        if (error != std::errc{}) invalid();
        append(std::string_view(buffer, static_cast<std::size_t>(end - buffer)));
      } else if constexpr (std::same_as<T, std::string>) string(item);
      else if constexpr (std::same_as<T, array>) {
        if (depth >= bounds_.depth) invalid();
        character('[');
        bool first = true;
        for (const auto& child : item) {
          if (!first) character(',');
          first = false;
          write_value(child, depth + 1);
        }
        character(']');
      } else if constexpr (std::same_as<T, object>) {
        if (depth >= bounds_.depth) invalid();
        character('{');
        bool first = true;
        for (const auto& [key, child] : item) {
          if (!first) character(',');
          first = false;
          node();
          string(key);
          character(':');
          write_value(child, depth + 1);
        }
        character('}');
      }
    }, document.data);
  }
};
}  // namespace

value parse(std::string_view document, limits bounds) { return parser(document, bounds).run(); }
std::string serialize(const value& document, limits bounds) { return serializer(bounds).run(document); }

}  // namespace ipms::agent::management_json
