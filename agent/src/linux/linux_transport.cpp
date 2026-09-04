#include "ipms/agent/linux_transport.hpp"

#include "ipms/agent/linux_inventory.hpp"

#include <curl/curl.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>

namespace {
constexpr std::string_view k_agent_version = "0.2.8";
constexpr std::size_t k_max_document_bytes = 65'536;

struct curl_cleanup { void operator()(CURL* value) const { if (value) curl_easy_cleanup(value); } };
struct bio_cleanup { void operator()(BIO* value) const { if (value) BIO_free(value); } };
struct key_cleanup { void operator()(EVP_PKEY* value) const { if (value) EVP_PKEY_free(value); } };
struct key_context_cleanup { void operator()(EVP_PKEY_CTX* value) const { if (value) EVP_PKEY_CTX_free(value); } };
struct request_cleanup { void operator()(X509_REQ* value) const { if (value) X509_REQ_free(value); } };
struct certificate_cleanup { void operator()(X509* value) const { if (value) X509_free(value); } };
using curl_handle = std::unique_ptr<CURL, curl_cleanup>;
using bio_handle = std::unique_ptr<BIO, bio_cleanup>;
using key_handle = std::unique_ptr<EVP_PKEY, key_cleanup>;
using key_context = std::unique_ptr<EVP_PKEY_CTX, key_context_cleanup>;
using request_handle = std::unique_ptr<X509_REQ, request_cleanup>;
using certificate_handle = std::unique_ptr<X509, certificate_cleanup>;

struct state {
  std::string device_uri;
  std::string gateway;
  std::uint16_t port{};
};

struct http_response {
  long status{};
  std::string body;
};

struct certificate_pin {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
};

std::filesystem::path data_directory() {
  const char* override_path = std::getenv("IPMS_AGENT_DATA_DIR");
  return override_path && *override_path ? std::filesystem::path(override_path)
                                         : std::filesystem::path("/var/lib/ipms-agent");
}

std::string json_escape(std::string_view value) {
  std::ostringstream output;
  for (const unsigned char character : value) {
    switch (character) {
      case '"': output << "\\\""; break;
      case '\\': output << "\\\\"; break;
      case '\b': output << "\\b"; break;
      case '\f': output << "\\f"; break;
      case '\n': output << "\\n"; break;
      case '\r': output << "\\r"; break;
      case '\t': output << "\\t"; break;
      default:
        if (character < 0x20) throw std::runtime_error("A JSON value contains a control character.");
        output << static_cast<char>(character);
    }
  }
  return output.str();
}

std::optional<std::string> json_string(const std::string& document, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  auto position = document.find(marker);
  if (position == std::string::npos) return std::nullopt;
  position = document.find(':', position + marker.size());
  if (position == std::string::npos) return std::nullopt;
  position = document.find_first_not_of(" \t\r\n", position + 1);
  if (position == std::string::npos || document[position] != '"') return std::nullopt;
  std::string value;
  for (++position; position < document.size(); ++position) {
    const char character = document[position];
    if (character == '"') return value;
    if (character != '\\') { value.push_back(character); continue; }
    if (++position >= document.size()) return std::nullopt;
    switch (document[position]) {
      case '"': value.push_back('"'); break;
      case '\\': value.push_back('\\'); break;
      case '/': value.push_back('/'); break;
      case 'b': value.push_back('\b'); break;
      case 'f': value.push_back('\f'); break;
      case 'n': value.push_back('\n'); break;
      case 'r': value.push_back('\r'); break;
      case 't': value.push_back('\t'); break;
      default: return std::nullopt;
    }
  }
  return std::nullopt;
}

std::optional<std::uint16_t> json_port(const std::string& document, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  auto position = document.find(marker);
  if (position == std::string::npos) return std::nullopt;
  position = document.find(':', position + marker.size());
  if (position == std::string::npos) return std::nullopt;
  position = document.find_first_not_of(" \t\r\n", position + 1);
  unsigned long value = 0;
  if (position == std::string::npos || !std::isdigit(static_cast<unsigned char>(document[position]))) return std::nullopt;
  while (position < document.size() && std::isdigit(static_cast<unsigned char>(document[position]))) {
    value = value * 10 + static_cast<unsigned>(document[position++] - '0');
    if (value > 65'535) return std::nullopt;
  }
  return value == 0 ? std::nullopt : std::optional<std::uint16_t>(static_cast<std::uint16_t>(value));
}

std::string read_bounded_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("The Agent bootstrap or state file could not be read.");
  std::string value((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (value.empty() || value.size() > k_max_document_bytes) throw std::runtime_error("The Agent state file size is invalid.");
  return value;
}

void write_private_file(const std::filesystem::path& path, std::string_view value) {
  std::filesystem::create_directories(path.parent_path());
  const auto temporary = path.string() + ".new";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("The Agent state could not be written.");
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.flush();
    if (!output) throw std::runtime_error("The Agent state could not be committed.");
  }
  std::filesystem::permissions(temporary, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace);
  std::filesystem::rename(temporary, path);
}

std::string normalized_fingerprint(std::string value) {
  std::string result;
  for (const unsigned char character : value) {
    if (std::isxdigit(character)) result.push_back(static_cast<char>(std::tolower(character)));
  }
  if (result.size() > 64) result = result.substr(result.size() - 64);
  return result;
}

certificate_pin parse_pin(const std::string& value) {
  const auto normalized = normalized_fingerprint(value);
  if (normalized.size() != 64) throw std::runtime_error("The bootstrap certificate fingerprint is invalid.");
  certificate_pin result;
  for (std::size_t index = 0; index < result.digest.size(); ++index) {
    const auto byte = normalized.substr(index * 2, 2);
    result.digest[index] = static_cast<unsigned char>(std::stoul(byte, nullptr, 16));
  }
  return result;
}

int verify_pinned_certificate(X509_STORE_CTX* context, void* argument) {
  auto* pin = static_cast<certificate_pin*>(argument);
  X509* certificate = X509_STORE_CTX_get0_cert(context);
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int digest_length = 0;
  if (!pin || !certificate || X509_digest(certificate, EVP_sha256(), digest.data(), &digest_length) != 1 ||
      digest_length != pin->digest.size()) return 0;
  return std::equal(pin->digest.begin(), pin->digest.end(), digest.begin()) ? 1 : 0;
}

CURLcode configure_pinned_ssl(CURL*, void* ssl_context, void* argument) {
  SSL_CTX_set_cert_verify_callback(static_cast<SSL_CTX*>(ssl_context), verify_pinned_certificate, argument);
  return CURLE_OK;
}

std::size_t receive_body(char* data, std::size_t size, std::size_t count, void* target) {
  auto& body = *static_cast<std::string*>(target);
  const auto bytes = size * count;
  if (bytes > k_max_document_bytes || body.size() > k_max_document_bytes - bytes) return 0;
  body.append(data, bytes);
  return bytes;
}

http_response post_json(const state& identity, std::string_view path, std::string_view body,
                        certificate_pin* pin = nullptr) {
  curl_handle curl(curl_easy_init());
  if (!curl) throw std::runtime_error("The Agent HTTP session could not be created.");
  std::string response;
  const std::string url = "https://" + identity.gateway + ':' + std::to_string(identity.port) + std::string(path);
  curl_slist* raw_headers = curl_slist_append(nullptr, "Content-Type: application/json");
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(raw_headers, curl_slist_free_all);
  curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
  curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, receive_body);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
  curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 45L);
  curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
  curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl.get(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
#ifdef CURLOPT_PROTOCOLS_STR
  curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "https");
#endif
  if (pin) {
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_CTX_FUNCTION, configure_pinned_ssl);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_CTX_DATA, pin);
  } else {
    const auto directory = data_directory();
    const auto ca = (directory / "ca-chain.pem").string();
    const auto certificate = (directory / "agent-certificate.pem").string();
    const auto key = (directory / "agent-key.pem").string();
    curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, certificate.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_SSLKEY, key.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
  }
  const auto result = curl_easy_perform(curl.get());
  if (result != CURLE_OK) throw std::runtime_error(std::string("The Agent Gateway TLS request failed: ") + curl_easy_strerror(result));
  long status = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
  return {status, std::move(response)};
}

std::string bio_string(BIO* bio) {
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio, &data);
  if (length <= 0 || !data) throw std::runtime_error("The Agent certificate material could not be encoded.");
  return std::string(data, static_cast<std::size_t>(length));
}

std::pair<key_handle, std::string> create_enrollment_request(const std::string& hostname) {
  key_context context(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
  if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context.get(), NID_X9_62_prime256v1) <= 0)
    throw std::runtime_error("The Agent ECDSA key could not be initialized.");
  EVP_PKEY* raw_key = nullptr;
  if (EVP_PKEY_keygen(context.get(), &raw_key) <= 0) throw std::runtime_error("The Agent ECDSA key could not be created.");
  key_handle key(raw_key);
  request_handle request(X509_REQ_new());
  if (!request || X509_REQ_set_version(request.get(), 0L) != 1 || X509_REQ_set_pubkey(request.get(), key.get()) != 1)
    throw std::runtime_error("The Agent certificate request could not be initialized.");
  X509_NAME* subject = X509_REQ_get_subject_name(request.get());
  const auto common_name = "IPMS Agent " + hostname;
  if (!subject || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
      reinterpret_cast<const unsigned char*>(common_name.data()), static_cast<int>(common_name.size()), -1, 0) != 1 ||
      X509_REQ_sign(request.get(), key.get(), EVP_sha256()) <= 0)
    throw std::runtime_error("The Agent certificate request could not be signed.");
  bio_handle request_bio(BIO_new(BIO_s_mem()));
  if (!request_bio || PEM_write_bio_X509_REQ(request_bio.get(), request.get()) != 1)
    throw std::runtime_error("The Agent certificate request could not be encoded.");
  return {std::move(key), bio_string(request_bio.get())};
}

void persist_private_key(const std::filesystem::path& path, EVP_PKEY* key) {
  bio_handle bio(BIO_new(BIO_s_mem()));
  if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    throw std::runtime_error("The Agent private key could not be encoded.");
  write_private_file(path, bio_string(bio.get()));
}

std::string local_hostname() {
  std::array<char, 256> hostname{};
  if (gethostname(hostname.data(), hostname.size() - 1) != 0) throw std::runtime_error("The Linux hostname is unavailable.");
  return hostname.data();
}

state load_state(const std::filesystem::path& path) {
  const auto document = read_bounded_file(path);
  const auto device_uri = json_string(document, "device_uri");
  const auto gateway = json_string(document, "gateway_dns_name");
  const auto port = json_port(document, "gateway_port");
  if (!device_uri || !gateway || !port || !device_uri->starts_with("urn:ipms:agent:"))
    throw std::runtime_error("The Agent state is invalid.");
  return {*device_uri, *gateway, *port};
}

state enroll(const std::filesystem::path& bootstrap_path, const std::filesystem::path& state_path) {
  std::string bootstrap = read_bounded_file(bootstrap_path);
  const auto device_uri = json_string(bootstrap, "device_uri");
  const auto gateway = json_string(bootstrap, "gateway_dns_name");
  const auto port = json_port(bootstrap, "gateway_port");
  const auto raw_pin = json_string(bootstrap, "gateway_fingerprint_sha256");
  auto token = json_string(bootstrap, "bootstrap_token");
  if (!device_uri || !gateway || !port || !raw_pin || !token || !device_uri->starts_with("urn:ipms:agent:"))
    throw std::runtime_error("The Agent bootstrap document is invalid.");
  auto pin = parse_pin(*raw_pin);
  auto [key, csr] = create_enrollment_request(local_hostname());
  const state identity{*device_uri, *gateway, *port};
  const std::string body = "{\"type\":\"enroll\",\"bootstrap_token\":\"" + json_escape(*token) +
                           "\",\"csr_pem\":\"" + json_escape(csr) + "\"}";
  const auto response = post_json(identity, "/v1/enroll", body, &pin);
  std::fill(token->begin(), token->end(), '\0');
  if (response.status != 200) throw std::runtime_error("The Agent enrollment was rejected.");
  const auto returned_uri = json_string(response.body, "device_uri");
  const auto certificate_pem = json_string(response.body, "certificate_pem");
  const auto chain_pem = json_string(response.body, "certificate_chain_pem");
  if (!returned_uri || *returned_uri != *device_uri || !certificate_pem || !chain_pem)
    throw std::runtime_error("The Agent enrollment response is invalid.");
  bio_handle certificate_bio(BIO_new_mem_buf(certificate_pem->data(), static_cast<int>(certificate_pem->size())));
  certificate_handle certificate(PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr));
  if (!certificate || X509_check_private_key(certificate.get(), key.get()) != 1)
    throw std::runtime_error("The Agent certificate does not match its private key.");
  const auto directory = state_path.parent_path();
  persist_private_key(directory / "agent-key.pem", key.get());
  write_private_file(directory / "agent-certificate.pem", *certificate_pem);
  write_private_file(directory / "ca-chain.pem", *chain_pem);
  write_private_file(state_path, "{\"device_uri\":\"" + json_escape(*device_uri) +
      "\",\"gateway_dns_name\":\"" + json_escape(*gateway) + "\",\"gateway_port\":" +
      std::to_string(*port) + "}");
  std::fill(bootstrap.begin(), bootstrap.end(), '\0');
  std::error_code ignored;
  std::filesystem::remove(bootstrap_path, ignored);
  return identity;
}
}  // namespace

namespace ipms::agent::linux {

TransportResult run_inventory_cycle() {
  try {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) throw std::runtime_error("The Agent TLS runtime could not be initialized.");
    const auto directory = data_directory();
    const auto state_path = directory / "agent-state.json";
    const auto bootstrap_path = directory / "enrollment.json";
    const state identity = std::filesystem::exists(state_path) ? load_state(state_path) : enroll(bootstrap_path, state_path);
    const std::string inventory_body = "{\"type\":\"inventory\",\"device_uri\":\"" +
        json_escape(identity.device_uri) + "\",\"correlation_id\":\"linux-agent-cycle\",\"agent_version\":\"" +
        std::string(k_agent_version) + "\",\"inventory\":" + collect_linux_inventory_json() + "}";
    const auto inventory_response = post_json(identity, "/v1/inventory", inventory_body);
    if (inventory_response.status != 200 || json_string(inventory_response.body, "type") != std::optional<std::string>("accepted"))
      throw std::runtime_error("The Agent inventory was rejected.");
    for (const auto& software : collect_linux_software_inventory_pages()) {
      const std::string body = "{\"type\":\"software_inventory\",\"device_uri\":\"" +
          json_escape(identity.device_uri) + "\",\"correlation_id\":\"linux-agent-software\",\"agent_version\":\"" +
          std::string(k_agent_version) + "\",\"software_inventory\":" + software + "}";
      if (body.size() > k_max_document_bytes) throw std::runtime_error("The Agent software inventory page is too large.");
      const auto response = post_json(identity, "/v1/software-inventory", body);
      if (response.status != 200 || json_string(response.body, "type") != std::optional<std::string>("accepted"))
        throw std::runtime_error("The Agent software inventory was rejected.");
    }
    curl_global_cleanup();
    return {true, "Enrollment and inventory delivery succeeded."};
  } catch (const std::exception& error) {
    curl_global_cleanup();
    return {false, error.what()};
  }
}

}  // namespace ipms::agent::linux
