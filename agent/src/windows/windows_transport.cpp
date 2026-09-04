#include "ipms/agent/windows_transport.hpp"

#include "ipms/agent/configuration.hpp"
#include "ipms/agent/hyperv_pack.hpp"
#include "ipms/agent/windows_core_pack.hpp"
#include "ipms/agent/windows_telemetry.hpp"
#include "ipms/agent/windows_software_pack.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <certenroll.h>
#include <wrl/client.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Microsoft::WRL::ComPtr;
constexpr std::size_t k_max_document_bytes = 65'536;
constexpr wchar_t k_agent_version[] = L"0.2.5";
constexpr std::size_t k_max_artifact_bytes = 64 * 1024 * 1024;

struct internet_closer { void operator()(void* handle) const { if (handle) WinHttpCloseHandle(handle); } };
using internet_handle = std::unique_ptr<void, internet_closer>;
struct cert_closer { void operator()(const CERT_CONTEXT* value) const { if (value) CertFreeCertificateContext(value); } };
using cert_context = std::unique_ptr<const CERT_CONTEXT, cert_closer>;
struct store_closer { void operator()(void* value) const { if (value) CertCloseStore(value, 0); } };
using cert_store = std::unique_ptr<void, store_closer>;
struct bstr_closer { void operator()(OLECHAR* value) const { if (value) SysFreeString(value); } };
using bstr = std::unique_ptr<OLECHAR, bstr_closer>;

struct com_scope {
  bool initialized{false};
  com_scope() {
    const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    initialized = SUCCEEDED(result);
    if (FAILED(result) && result != RPC_E_CHANGED_MODE)
      throw std::runtime_error("Windows certificate enrollment could not be initialized.");
  }
  ~com_scope() { if (initialized) CoUninitialize(); }
};

std::filesystem::path data_directory() {
  wchar_t program_data[MAX_PATH]{};
  const auto length = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
  return (length == 0 ? std::filesystem::path(L"C:\\ProgramData") : std::filesystem::path(program_data)) /
         L"Alvestrasza" / L"IPMS Agent";
}

std::string utf8(const std::wstring& value) {
  if (value.empty()) return {};
  const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
  if (count <= 0) throw std::runtime_error("UTF-8 conversion failed.");
  std::string result(count, '\0');
  if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count, nullptr, nullptr))
    throw std::runtime_error("UTF-8 conversion failed.");
  return result;
}

std::wstring wide(const std::string& value) {
  if (value.empty()) return {};
  const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (count <= 0) throw std::runtime_error("UTF-8 conversion failed.");
  std::wstring result(count, L'\0');
  if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), count))
    throw std::runtime_error("UTF-8 conversion failed.");
  return result;
}

std::string json_escape(const std::string& value) {
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

std::optional<std::string> json_object(const std::string& document, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  auto position = document.find(marker);
  if (position == std::string::npos) return std::nullopt;
  position = document.find(':', position + marker.size());
  if (position == std::string::npos) return std::nullopt;
  position = document.find_first_not_of(" \t\r\n", position + 1);
  if (position == std::string::npos || document[position] != '{') return std::nullopt;
  const auto start = position;
  unsigned depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (; position < document.size(); ++position) {
    const char character = document[position];
    if (in_string) {
      if (escaped) escaped = false;
      else if (character == '\\') escaped = true;
      else if (character == '"') in_string = false;
      continue;
    }
    if (character == '"') in_string = true;
    else if (character == '{') ++depth;
    else if (character == '}' && --depth == 0) return document.substr(start, position - start + 1);
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
  if (position == std::string::npos || !std::isdigit(static_cast<unsigned char>(document[position]))) return std::nullopt;
  unsigned long value = 0;
  while (position < document.size() && std::isdigit(static_cast<unsigned char>(document[position]))) {
    value = value * 10 + static_cast<unsigned>(document[position++] - '0');
    if (value > 65'535) return std::nullopt;
  }
  return value == 0 ? std::nullopt : std::optional<std::uint16_t>(static_cast<std::uint16_t>(value));
}

std::array<unsigned, 3> version_tuple(const std::string& value) {
  std::array<unsigned, 3> result{};
  std::size_t position = 0;
  for (std::size_t index = 0; index < result.size(); ++index) {
    if (position >= value.size() || !std::isdigit(static_cast<unsigned char>(value[position])))
      throw std::runtime_error("The Agent lifecycle version is invalid.");
    unsigned component = 0;
    while (position < value.size() && std::isdigit(static_cast<unsigned char>(value[position]))) {
      component = component * 10 + static_cast<unsigned>(value[position++] - '0');
      if (component > 65'535) throw std::runtime_error("The Agent lifecycle version is invalid.");
    }
    result[index] = component;
    if (index + 1 < result.size()) {
      if (position >= value.size() || value[position++] != '.')
        throw std::runtime_error("The Agent lifecycle version is invalid.");
    }
  }
  if (position != value.size()) throw std::runtime_error("The Agent lifecycle version is invalid.");
  return result;
}

std::string read_bounded_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("The Agent bootstrap or state file could not be read.");
  std::string value((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (value.empty() || value.size() > k_max_document_bytes) throw std::runtime_error("The Agent bootstrap or state file size is invalid.");
  return value;
}

void write_atomically(const std::filesystem::path& path, const std::string& value) {
  std::filesystem::create_directories(path.parent_path());
  const auto temporary = path.wstring() + L".new";
  {
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("The Agent state could not be written.");
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.flush();
    if (!output) throw std::runtime_error("The Agent state could not be written.");
  }
  if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw std::runtime_error("The Agent state could not be committed.");
}

std::string hex(const BYTE* bytes, DWORD length) {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (DWORD index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(bytes[index]);
  return output.str();
}

std::string certificate_sha256(PCCERT_CONTEXT certificate) {
  std::array<BYTE, 32> digest{};
  DWORD size = static_cast<DWORD>(digest.size());
  if (!CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr, certificate->pbCertEncoded,
                             certificate->cbCertEncoded, digest.data(), &size) || size != digest.size())
    throw std::runtime_error("The certificate fingerprint could not be calculated.");
  return hex(digest.data(), size);
}

std::string normalized_fingerprint(std::string value) {
  std::string result;
  for (const unsigned char character : value) if (std::isxdigit(character)) result.push_back(static_cast<char>(std::tolower(character)));
  if (result.size() > 64) result = result.substr(result.size() - 64);
  return result;
}

cert_context decode_certificate(const std::string& encoded) {
  DWORD size = 0;
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64HEADER, nullptr, &size, nullptr, nullptr))
    throw std::runtime_error("The certificate response is invalid.");
  std::vector<BYTE> der(size);
  if (!CryptStringToBinaryA(encoded.c_str(), static_cast<DWORD>(encoded.size()), CRYPT_STRING_BASE64HEADER, der.data(), &size, nullptr, nullptr))
    throw std::runtime_error("The certificate response is invalid.");
  return cert_context(CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), size));
}

std::vector<std::string> pem_certificates(const std::string& chain) {
  constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
  constexpr std::string_view end = "-----END CERTIFICATE-----";
  std::vector<std::string> result;
  std::size_t position = 0;
  while ((position = chain.find(begin, position)) != std::string::npos) {
    const auto finish = chain.find(end, position);
    if (finish == std::string::npos) throw std::runtime_error("The certificate chain is invalid.");
    const auto length = finish + end.size() - position;
    result.push_back(chain.substr(position, length));
    position += length;
  }
  if (result.empty() || result.size() > 4) throw std::runtime_error("The certificate chain is invalid.");
  return result;
}

void install_chain(const std::string& chain) {
  const auto certificates = pem_certificates(chain);
  for (std::size_t index = 0; index < certificates.size(); ++index) {
    auto certificate = decode_certificate(certificates[index]);
    if (!certificate) throw std::runtime_error("The certificate chain is invalid.");
    const wchar_t* store_name = index + 1 == certificates.size() ? L"ROOT" : L"CA";
    cert_store store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                   CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, store_name));
    if (!store || !CertAddCertificateContextToStore(store.get(), certificate.get(), CERT_STORE_ADD_REPLACE_EXISTING, nullptr))
      throw std::runtime_error("The Agent trust chain could not be installed.");
  }
}

struct enrollment_request {
  ComPtr<IX509Enrollment> enrollment;
  std::string csr;
};

void require(HRESULT result, const char* message) {
  if (FAILED(result)) throw std::runtime_error(message);
}

enrollment_request create_enrollment_request(const std::wstring& hostname) {
  ComPtr<IX509PrivateKey> key;
  ComPtr<IObjectId> algorithm;
  ComPtr<IX509CertificateRequestPkcs10> request;
  ComPtr<IX500DistinguishedName> subject;
  ComPtr<IX509Enrollment> enrollment;
  require(CoCreateInstance(__uuidof(CX509PrivateKey), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&key)), "The Agent private key provider is unavailable.");
  require(CoCreateInstance(__uuidof(CObjectId), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&algorithm)), "The Agent key algorithm provider is unavailable.");
  require(CoCreateInstance(__uuidof(CX509CertificateRequestPkcs10), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&request)), "The Agent certificate request provider is unavailable.");
  require(CoCreateInstance(__uuidof(CX500DistinguishedName), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&subject)), "The Agent subject provider is unavailable.");
  require(CoCreateInstance(__uuidof(CX509Enrollment), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&enrollment)), "The Agent enrollment provider is unavailable.");
  bstr provider(SysAllocString(MS_KEY_STORAGE_PROVIDER));
  bstr oid(SysAllocString(L"1.2.840.10045.3.1.7"));
  bstr empty(SysAllocString(L""));
  bstr subject_name(SysAllocString((L"CN=IPMS Agent " + hostname).c_str()));
  if (!provider || !oid || !empty || !subject_name) throw std::bad_alloc();
  require(key->put_ProviderName(provider.get()), "The Agent key provider could not be selected.");
  require(key->put_MachineContext(VARIANT_TRUE), "The Agent machine key context could not be selected.");
  require(key->put_Length(256), "The Agent key length could not be selected.");
  require(key->put_KeySpec(XCN_AT_NONE), "The Agent key specification could not be selected.");
  require(key->put_ExportPolicy(XCN_NCRYPT_ALLOW_EXPORT_NONE), "The Agent key export policy could not be applied.");
  require(key->put_KeyUsage(XCN_NCRYPT_ALLOW_SIGNING_FLAG), "The Agent key usage could not be applied.");
  require(algorithm->InitializeFromValue(oid.get()), "The Agent ECDSA algorithm could not be selected.");
  require(key->put_Algorithm(algorithm.Get()), "The Agent ECDSA algorithm could not be applied.");
  require(request->InitializeFromPrivateKey(ContextMachine, key.Get(), empty.get()), "The Agent certificate request could not be initialized.");
  require(subject->Encode(subject_name.get(), XCN_CERT_NAME_STR_NONE), "The Agent certificate subject could not be encoded.");
  require(request->put_Subject(subject.Get()), "The Agent certificate subject could not be applied.");
  require(enrollment->InitializeFromRequest(request.Get()), "The Agent enrollment could not be initialized.");
  BSTR raw_csr = nullptr;
  require(enrollment->CreateRequest(XCN_CRYPT_STRING_BASE64REQUESTHEADER, &raw_csr), "The Agent certificate request could not be created.");
  bstr csr(raw_csr);
  std::string standard_csr = utf8(csr ? std::wstring(csr.get(), SysStringLen(csr.get())) : L"");
  constexpr std::string_view old_begin = "-----BEGIN NEW CERTIFICATE REQUEST-----";
  constexpr std::string_view new_begin = "-----BEGIN CERTIFICATE REQUEST-----";
  constexpr std::string_view old_end = "-----END NEW CERTIFICATE REQUEST-----";
  constexpr std::string_view new_end = "-----END CERTIFICATE REQUEST-----";
  const auto begin = standard_csr.find(old_begin);
  if (begin != std::string::npos) standard_csr.replace(begin, old_begin.size(), new_begin);
  const auto end = standard_csr.find(old_end);
  if (end != std::string::npos) standard_csr.replace(end, old_end.size(), new_end);
  enrollment_request result{enrollment, std::move(standard_csr)};
  return result;
}

struct state { std::string device_uri; std::string certificate_sha256; std::wstring gateway; std::uint16_t port{}; };
struct http_response { DWORD status{}; std::string body; };

http_response post_json(const std::wstring& hostname, std::uint16_t port, const std::wstring& path,
                        const std::string& body, const std::string* pin, PCCERT_CONTEXT client_certificate) {
  internet_handle session(WinHttpOpen(L"IPMS-Agent/0.2.5", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
  if (!session) throw std::runtime_error("The Agent HTTP session could not be created.");
  WinHttpSetTimeouts(session.get(), 10'000, 10'000, 30'000, 30'000);
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
  if (!WinHttpSetOption(session.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols)))
    throw std::runtime_error("TLS 1.3 could not be required.");
  internet_handle connection(WinHttpConnect(session.get(), hostname.c_str(), port, 0));
  if (!connection) throw std::runtime_error("The Agent Gateway connection could not be created.");
  internet_handle request(WinHttpOpenRequest(connection.get(), L"POST", path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  if (!request) throw std::runtime_error("The Agent Gateway request could not be created.");
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect));
  if (client_certificate) {
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                          const_cast<PCERT_CONTEXT>(client_certificate), sizeof(CERT_CONTEXT)))
      throw std::runtime_error("The Agent client certificate could not be selected.");
  } else {
    WinHttpSetOption(request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT, WINHTTP_NO_CLIENT_CERT_CONTEXT, 0);
  }
  if (pin) {
    DWORD security = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &security, sizeof(security)))
      throw std::runtime_error("The one-time bootstrap trust policy could not be applied.");
  }
  const wchar_t headers[] = L"Content-Type: application/json\r\n";
  if (!WinHttpSendRequest(request.get(), headers, static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0,
                          static_cast<DWORD>(body.size()), 0))
    throw std::runtime_error("The Agent Gateway TLS request failed.");
  if (pin) {
    PCCERT_CONTEXT raw_server_certificate = nullptr;
    DWORD size = sizeof(raw_server_certificate);
    if (!WinHttpQueryOption(request.get(), WINHTTP_OPTION_SERVER_CERT_CONTEXT, &raw_server_certificate, &size) || !raw_server_certificate)
      throw std::runtime_error("The Agent Gateway certificate could not be inspected.");
    cert_context server_certificate(raw_server_certificate);
    if (certificate_sha256(server_certificate.get()) != normalized_fingerprint(*pin))
      throw std::runtime_error("The Agent Gateway certificate pin does not match.");
  }
  DWORD written = 0;
  if (!WinHttpWriteData(request.get(), body.data(), static_cast<DWORD>(body.size()), &written) || written != body.size())
    throw std::runtime_error("The Agent Gateway request body could not be sent.");
  if (!WinHttpReceiveResponse(request.get(), nullptr)) throw std::runtime_error("The Agent Gateway response could not be received.");
  DWORD status = 0; DWORD status_size = sizeof(status);
  if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
    throw std::runtime_error("The Agent Gateway response status is unavailable.");
  std::string response;
  for (;;) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(request.get(), &available)) throw std::runtime_error("The Agent Gateway response is invalid.");
    if (available == 0) break;
    if (response.size() + available > k_max_document_bytes) throw std::runtime_error("The Agent Gateway response is too large.");
    const auto offset = response.size(); response.resize(offset + available);
    DWORD read = 0;
    if (!WinHttpReadData(request.get(), response.data() + offset, available, &read)) throw std::runtime_error("The Agent Gateway response is invalid.");
    response.resize(offset + read);
  }
  return {status, response};
}

http_response post_binary(const state& identity, const std::string& body, PCCERT_CONTEXT certificate) {
  internet_handle session(WinHttpOpen(L"IPMS-Agent/0.2.5", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
  if (!session) throw std::runtime_error("The Agent artifact session could not be created.");
  WinHttpSetTimeouts(session.get(), 10'000, 10'000, 60'000, 60'000);
  DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
  if (!WinHttpSetOption(session.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols)))
    throw std::runtime_error("TLS 1.3 could not be required.");
  internet_handle connection(WinHttpConnect(session.get(), identity.gateway.c_str(), identity.port, 0));
  if (!connection) throw std::runtime_error("The Agent artifact connection could not be created.");
  internet_handle request(WinHttpOpenRequest(connection.get(), L"POST", L"/v1/lifecycle-artifact", nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
  if (!request) throw std::runtime_error("The Agent artifact request could not be created.");
  DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
  WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect, sizeof(redirect));
  if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                        const_cast<PCERT_CONTEXT>(certificate), sizeof(CERT_CONTEXT)))
    throw std::runtime_error("The Agent client certificate could not be selected.");
  const wchar_t headers[] = L"Content-Type: application/json\r\n";
  if (!WinHttpSendRequest(request.get(), headers, static_cast<DWORD>(-1), WINHTTP_NO_REQUEST_DATA, 0,
                          static_cast<DWORD>(body.size()), 0))
    throw std::runtime_error("The Agent artifact TLS request failed.");
  DWORD written = 0;
  if (!WinHttpWriteData(request.get(), body.data(), static_cast<DWORD>(body.size()), &written) || written != body.size())
    throw std::runtime_error("The Agent artifact request body could not be sent.");
  if (!WinHttpReceiveResponse(request.get(), nullptr)) throw std::runtime_error("The Agent artifact response could not be received.");
  DWORD status = 0; DWORD status_size = sizeof(status);
  if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
    throw std::runtime_error("The Agent artifact response status is unavailable.");
  std::string response;
  for (;;) {
    DWORD available = 0;
    if (!WinHttpQueryDataAvailable(request.get(), &available)) throw std::runtime_error("The Agent artifact response is invalid.");
    if (available == 0) break;
    if (response.size() + available > k_max_artifact_bytes) throw std::runtime_error("The Agent artifact is too large.");
    const auto offset = response.size(); response.resize(offset + available);
    DWORD read = 0;
    if (!WinHttpReadData(request.get(), response.data() + offset, available, &read)) throw std::runtime_error("The Agent artifact response is invalid.");
    response.resize(offset + read);
  }
  return {status, response};
}

PCCERT_CONTEXT find_agent_certificate(const std::string& fingerprint) {
  cert_store store(CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                 CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"MY"));
  if (!store) return nullptr;
  PCCERT_CONTEXT current = nullptr;
  while ((current = CertEnumCertificatesInStore(store.get(), current)) != nullptr) {
    if (certificate_sha256(current) == normalized_fingerprint(fingerprint)) return CertDuplicateCertificateContext(current);
  }
  return nullptr;
}

std::wstring computer_name() {
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  std::wstring value(size, L'\0');
  if (!GetComputerNameW(value.data(), &size)) throw std::runtime_error("The Windows computer name is unavailable.");
  value.resize(size);
  return value;
}

state load_state(const std::filesystem::path& path) {
  const auto document = read_bounded_file(path);
  const auto device_uri = json_string(document, "device_uri");
  const auto fingerprint = json_string(document, "certificate_sha256");
  const auto gateway = json_string(document, "gateway_dns_name");
  const auto port = json_port(document, "gateway_port");
  if (!device_uri || !fingerprint || !gateway || !port ||
      !device_uri->starts_with("urn:ipms:agent:") || normalized_fingerprint(*fingerprint).size() != 64)
    throw std::runtime_error("The Agent state is invalid.");
  return {*device_uri, *fingerprint, wide(*gateway), *port};
}

std::string sha256(const std::string& value) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::array<unsigned char, 32> digest{};
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
    throw std::runtime_error("The Agent SHA-256 provider is unavailable.");
  const auto close_algorithm = [&]() { BCryptCloseAlgorithmProvider(algorithm, 0); };
  if (BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) != 0) {
    close_algorithm();
    throw std::runtime_error("The Agent SHA-256 hash could not be created.");
  }
  if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(value.data())),
                     static_cast<ULONG>(value.size()), 0) != 0 ||
      BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) != 0) {
    BCryptDestroyHash(hash);
    close_algorithm();
    throw std::runtime_error("The Agent artifact digest could not be calculated.");
  }
  BCryptDestroyHash(hash);
  close_algorithm();
  return hex(digest.data(), static_cast<DWORD>(digest.size()));
}

bool safe_lifecycle_value(const std::string& value, std::size_t maximum = 64) {
  return !value.empty() && value.size() <= maximum &&
         std::all_of(value.begin(), value.end(), [](const unsigned char character) {
           return std::isalnum(character) || character == '-' || character == '.' || character == '_';
         });
}

bool safe_vm_name(const std::string& value) {
  return !value.empty() && value.size() <= 255 &&
         std::all_of(value.begin(), value.end(), [](const unsigned char character) {
           return character >= 0x20 && character != 0x7f;
         });
}

void report_result(const state& identity, PCCERT_CONTEXT certificate, const std::string& job_id,
                   const std::string& result, const std::string& result_code) {
  if (!safe_lifecycle_value(job_id) || !safe_lifecycle_value(result, 16) ||
      !safe_lifecycle_value(result_code))
    throw std::runtime_error("The Agent lifecycle result is invalid.");
  const std::string body = "{\"type\":\"lifecycle_result\",\"device_uri\":\"" +
                           json_escape(identity.device_uri) + "\",\"correlation_id\":\"lifecycle-" +
                           json_escape(job_id) + "\",\"job_id\":\"" + json_escape(job_id) +
                           "\",\"result\":\"" + json_escape(result) + "\",\"result_code\":\"" +
                           json_escape(result_code) + "\"}";
  const auto response = post_json(identity.gateway, identity.port, L"/v1/lifecycle-result", body, nullptr, certificate);
  if (response.status != 200 || json_string(response.body, "type") != std::optional<std::string>("accepted"))
    throw std::runtime_error("The Agent lifecycle result was rejected.");
}

std::filesystem::path executable_directory() {
  std::wstring buffer(32'768, L'\0');
  const auto length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size())
    throw std::runtime_error("The Agent installation directory is unavailable.");
  buffer.resize(length);
  return std::filesystem::path(buffer).parent_path();
}

void launch_updater(const std::string& job_id, const std::string& action,
                    const std::string& target_version, const std::string& expected_sha256,
                    const std::filesystem::path& staged_binary) {
  const auto source = executable_directory() / L"ipms-agent.exe";
  const auto update_directory = data_directory() / L"updates" / wide(job_id);
  std::filesystem::create_directories(update_directory);
  const auto updater = update_directory / L"ipms-agent-update-runner.exe";
  if (!CopyFileW(source.c_str(), updater.c_str(), FALSE))
    throw std::runtime_error("The fixed Agent updater could not be staged.");
  std::wstring command = L"\"" + updater.wstring() + L"\" --apply-lifecycle-update --job \"" + wide(job_id) +
                         L"\" --action \"" + wide(action) + L"\" --version \"" +
                         wide(target_version.empty() ? "none" : target_version) + L"\" --sha256 \"" +
                         wide(expected_sha256.empty() ? "none" : expected_sha256) + L"\" --staged \"" +
                         staged_binary.wstring() + L"\"";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                      updater.parent_path().c_str(), &startup, &process))
    throw std::runtime_error("The fixed Agent updater could not be started.");
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
}

void process_lifecycle_assignment(const std::string& response_document, const state& identity,
                                  PCCERT_CONTEXT certificate) {
  const auto assignment = json_object(response_document, "lifecycle");
  if (!assignment) return;
  const auto job_id = json_string(*assignment, "job_id");
  const auto action = json_string(*assignment, "action");
  if (!job_id || !action) return;
  const auto target_version = json_string(*assignment, "target_version").value_or("");
  const auto expected_sha256 = normalized_fingerprint(
      json_string(*assignment, "artifact_sha256").value_or(""));
  if (!safe_lifecycle_value(*job_id) || (*action != "update" && *action != "uninstall"))
    throw std::runtime_error("The Agent lifecycle assignment is invalid.");
  std::filesystem::path staged_binary;
  if (*action == "update") {
    if (!safe_lifecycle_value(target_version) || expected_sha256.size() != 64)
      throw std::runtime_error("The Agent update assignment is invalid.");
    if (version_tuple(target_version) <= version_tuple(utf8(k_agent_version)))
      throw std::runtime_error("The Agent update assignment is not a monotonic upgrade.");
    const std::string request = "{\"type\":\"lifecycle_artifact\",\"device_uri\":\"" +
                                json_escape(identity.device_uri) + "\",\"job_id\":\"" +
                                json_escape(*job_id) + "\"}";
    const auto artifact = post_binary(identity, request, certificate);
    if (artifact.status != 200 || sha256(artifact.body) != expected_sha256)
      throw std::runtime_error("The Agent update artifact failed verification.");
    staged_binary = data_directory() / L"updates" / wide(*job_id) / L"ipms-agent.exe";
    write_atomically(staged_binary, artifact.body);
  }
  report_result(identity, certificate, *job_id, "running", "accepted");
  launch_updater(*job_id, *action, target_version, expected_sha256, staged_binary);
}

void report_hyperv_action_result(
    const state& identity,
    PCCERT_CONTEXT certificate,
    const std::string& job_id,
    const std::string& result,
    const std::string& result_code) {
  if (!safe_lifecycle_value(job_id) || !safe_lifecycle_value(result, 16) ||
      !safe_lifecycle_value(result_code)) {
    throw std::runtime_error("The Hyper-V virtual machine action result is invalid.");
  }
  const std::string body =
      "{\"type\":\"hyperv_action_result\",\"device_uri\":\"" +
      json_escape(identity.device_uri) + "\",\"correlation_id\":\"hyperv-" +
      json_escape(job_id) + "\",\"job_id\":\"" + json_escape(job_id) +
      "\",\"result\":\"" + json_escape(result) + "\",\"result_code\":\"" +
      json_escape(result_code) + "\"}";
  const auto response = post_json(
      identity.gateway, identity.port, L"/v1/hyperv-action-result", body, nullptr, certificate);
  if (response.status != 200 ||
      json_string(response.body, "type") != std::optional<std::string>("accepted")) {
    throw std::runtime_error("The Hyper-V virtual machine action result was rejected.");
  }
}

void process_hyperv_action_assignment(
    const std::string& response_document,
    const state& identity,
    PCCERT_CONTEXT certificate) {
  const auto assignment = json_object(response_document, "hyperv_action");
  if (!assignment) return;
  const auto job_id = json_string(*assignment, "job_id");
  const auto action = json_string(*assignment, "action");
  const auto vm_source_id = json_string(*assignment, "vm_source_id");
  const auto vm_name = json_string(*assignment, "vm_name");
  const auto expected_state = json_string(*assignment, "expected_state");
  if (!job_id || !action || !vm_source_id || !vm_name || !expected_state ||
      !safe_lifecycle_value(*job_id) ||
      (*action != "start" && *action != "shutdown" && *action != "stop" &&
       *action != "pause" && *action != "resume") ||
      !safe_lifecycle_value(*vm_source_id) ||
      !safe_vm_name(*vm_name) ||
      (*expected_state != "running" && *expected_state != "stopped" && *expected_state != "paused")) {
    throw std::runtime_error("The Hyper-V virtual machine action assignment is invalid.");
  }
  const std::string locally_expected =
      (*action == "shutdown" || *action == "stop")
          ? "stopped"
          : ((*action == "pause") ? "paused" : "running");
  if (*expected_state != locally_expected) {
    throw std::runtime_error("The Hyper-V virtual machine action contract does not match.");
  }
  report_hyperv_action_result(identity, certificate, *job_id, "running", "accepted");
  const auto result = ipms::agent::windows::execute_hyperv_virtual_machine_action(
      *vm_source_id, *vm_name, *action);
  try {
    report_hyperv_action_result(
        identity,
        certificate,
        *job_id,
        result.succeeded ? "succeeded" : "failed",
        result.result_code);
  } catch (...) {
    const std::string pending =
        "{\"job_id\":\"" + json_escape(*job_id) + "\",\"result\":\"" +
        (result.succeeded ? "succeeded" : "failed") + "\",\"result_code\":\"" +
        json_escape(result.result_code) + "\"}";
    write_atomically(data_directory() / L"hyperv-action-result.json", pending);
    throw;
  }
}

void report_pending_hyperv_action_result(const state& identity, PCCERT_CONTEXT certificate) {
  const auto path = data_directory() / L"hyperv-action-result.json";
  if (!std::filesystem::is_regular_file(path)) return;
  const auto document = read_bounded_file(path);
  const auto job_id = json_string(document, "job_id");
  const auto result = json_string(document, "result");
  const auto code = json_string(document, "result_code");
  if (!job_id || !result || !code) {
    throw std::runtime_error("The pending Hyper-V virtual machine action result is invalid.");
  }
  report_hyperv_action_result(identity, certificate, *job_id, *result, *code);
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

void report_pending_result(const state& identity, PCCERT_CONTEXT certificate) {
  const auto path = data_directory() / L"lifecycle-result.json";
  if (!std::filesystem::is_regular_file(path)) return;
  const auto document = read_bounded_file(path);
  const auto job_id = json_string(document, "job_id");
  const auto result = json_string(document, "result");
  const auto code = json_string(document, "result_code");
  if (!job_id || !result || !code) throw std::runtime_error("The pending Agent lifecycle result is invalid.");
  report_result(identity, certificate, *job_id, *result, *code);
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}

void write_local_configuration(const std::filesystem::path& directory, const std::string& gateway, std::uint16_t port) {
  const std::string settings = "gateway_hostname=" + gateway + "\n" +
                               "gateway_port=" + std::to_string(port) + "\n" +
                               "trust_mode=ipms_managed\n";
  write_atomically(directory / L"agent-settings.ini", settings);
}

state enroll(const std::filesystem::path& bootstrap_path, const std::filesystem::path& state_path) {
  std::string bootstrap = read_bounded_file(bootstrap_path);
  const auto device_uri = json_string(bootstrap, "device_uri");
  const auto gateway = json_string(bootstrap, "gateway_dns_name");
  const auto port = json_port(bootstrap, "gateway_port");
  const auto pin = json_string(bootstrap, "gateway_fingerprint_sha256");
  auto token = json_string(bootstrap, "bootstrap_token");
  if (!device_uri || !gateway || !port || !pin || !token || normalized_fingerprint(*pin).size() != 64)
    throw std::runtime_error("The Agent bootstrap document is invalid.");
  auto request = create_enrollment_request(computer_name());
  const std::string body = "{\"type\":\"enroll\",\"bootstrap_token\":\"" + json_escape(*token) +
                           "\",\"csr_pem\":\"" + json_escape(request.csr) + "\"}";
  const auto response = post_json(wide(*gateway), *port, L"/v1/enroll", body, &*pin, nullptr);
  std::fill(token->begin(), token->end(), '\0');
  if (response.status != 200) throw std::runtime_error("The Agent enrollment was rejected.");
  const auto response_device_uri = json_string(response.body, "device_uri");
  const auto certificate_pem = json_string(response.body, "certificate_pem");
  const auto chain_pem = json_string(response.body, "certificate_chain_pem");
  if (!response_device_uri || *response_device_uri != *device_uri || !certificate_pem || !chain_pem)
    throw std::runtime_error("The Agent enrollment response is invalid.");
  install_chain(*chain_pem);
  bstr certificate(SysAllocString(wide(*certificate_pem).c_str()));
  bstr password(SysAllocString(L""));
  if (!certificate || !password) throw std::bad_alloc();
  require(request.enrollment->InstallResponse(static_cast<InstallResponseRestrictionFlags>(
                                                  AllowUntrustedCertificate | AllowUntrustedRoot),
                                              certificate.get(), XCN_CRYPT_STRING_BASE64HEADER, password.get()),
          "The Agent certificate could not be installed.");
  auto decoded = decode_certificate(*certificate_pem);
  if (!decoded) throw std::runtime_error("The Agent certificate response is invalid.");
  const auto fingerprint = certificate_sha256(decoded.get());
  const std::string persisted = "{\"device_uri\":\"" + json_escape(*device_uri) +
                                "\",\"certificate_sha256\":\"" + fingerprint +
                                "\",\"gateway_dns_name\":\"" + json_escape(*gateway) +
                                "\",\"gateway_port\":" + std::to_string(*port) + "}";
  write_atomically(state_path, persisted);
  write_local_configuration(state_path.parent_path(), *gateway, *port);
  std::fill(bootstrap.begin(), bootstrap.end(), '\0');
  std::error_code ignored; std::filesystem::remove(bootstrap_path, ignored);
  return {*device_uri, fingerprint, wide(*gateway), *port};
}
}  // namespace

namespace ipms::agent::windows {
TransportResult run_inventory_cycle() {
  try {
    com_scope com;
    const auto directory = data_directory();
    const auto state_path = directory / L"agent-state.json";
    const auto bootstrap_path = directory / L"enrollment.json";
    state identity = std::filesystem::exists(state_path) ? load_state(state_path) : enroll(bootstrap_path, state_path);
    cert_context certificate(find_agent_certificate(identity.certificate_sha256));
    if (!certificate) throw std::runtime_error("The enrolled Agent certificate is unavailable.");
    report_pending_result(identity, certificate.get());
    report_pending_hyperv_action_result(identity, certificate.get());
    const auto inventory = collect_windows_server_core_inventory_json();
    const std::string body = "{\"type\":\"inventory\",\"device_uri\":\"" + json_escape(identity.device_uri) +
                             "\",\"correlation_id\":\"windows-agent-cycle\",\"agent_version\":\"" +
                             utf8(k_agent_version) + "\",\"inventory\":" + inventory + "}";
    const auto response = post_json(identity.gateway, identity.port, L"/v1/inventory", body, nullptr, certificate.get());
    if (response.status != 200 || json_string(response.body, "type") != std::optional<std::string>("accepted"))
      throw std::runtime_error("The Agent inventory was rejected.");
    for (const auto& software_inventory : collect_windows_software_inventory_pages()) {
      const std::string software_body =
          "{\"type\":\"software_inventory\",\"device_uri\":\"" +
          json_escape(identity.device_uri) +
          "\",\"correlation_id\":\"windows-agent-software\",\"agent_version\":\"" +
          utf8(k_agent_version) + "\",\"software_inventory\":" + software_inventory + "}";
      if (software_body.size() > k_max_document_bytes) {
        throw std::runtime_error("The Agent software inventory page is too large.");
      }
      const auto software_response = post_json(
          identity.gateway,
          identity.port,
          L"/v1/software-inventory",
          software_body,
          nullptr,
          certificate.get());
      if (software_response.status != 200 ||
          json_string(software_response.body, "type") != std::optional<std::string>("accepted")) {
        throw std::runtime_error("The Agent software inventory was rejected.");
      }
    }
    process_lifecycle_assignment(response.body, identity, certificate.get());
    process_hyperv_action_assignment(response.body, identity, certificate.get());
    return {true, L"Enrollment and inventory delivery succeeded."};
  } catch (const std::exception& error) {
    try { return {false, wide(error.what())}; }
    catch (...) { return {false, L"The Agent connection cycle failed."}; }
  }
}

TransportResult run_telemetry_cycle() {
  try {
    const auto directory = data_directory();
    const auto state_path = directory / L"agent-state.json";
    if (!std::filesystem::exists(state_path)) {
      throw std::runtime_error("The Agent must complete enrollment before telemetry delivery.");
    }
    const state identity = load_state(state_path);
    cert_context certificate(find_agent_certificate(identity.certificate_sha256));
    if (!certificate) throw std::runtime_error("The enrolled Agent certificate is unavailable.");
    report_pending_result(identity, certificate.get());
    report_pending_hyperv_action_result(identity, certificate.get());
    const auto telemetry = collect_windows_telemetry_json();
    if (telemetry.empty()) throw std::runtime_error("The Agent telemetry snapshot is unavailable.");
    const std::string body = "{\"type\":\"telemetry\",\"device_uri\":\"" + json_escape(identity.device_uri) +
                             "\",\"correlation_id\":\"windows-agent-telemetry\",\"agent_version\":\"" +
                             utf8(k_agent_version) + "\",\"telemetry\":" + telemetry + "}";
    const auto response = post_json(identity.gateway, identity.port, L"/v1/telemetry", body, nullptr, certificate.get());
    if (response.status != 200 || json_string(response.body, "type") != std::optional<std::string>("accepted"))
      throw std::runtime_error("The Agent telemetry was rejected.");
    process_lifecycle_assignment(response.body, identity, certificate.get());
    process_hyperv_action_assignment(response.body, identity, certificate.get());
    return {true, L"Telemetry delivery succeeded."};
  } catch (const std::exception& error) {
    try { return {false, wide(error.what())}; }
    catch (...) { return {false, L"The Agent telemetry cycle failed."}; }
  }
}

TransportResult report_lifecycle_result(
    const std::string& job_id,
    const std::string& result,
    const std::string& result_code) {
  try {
    const state identity = load_state(data_directory() / L"agent-state.json");
    cert_context certificate(find_agent_certificate(identity.certificate_sha256));
    if (!certificate) throw std::runtime_error("The enrolled Agent certificate is unavailable.");
    report_result(identity, certificate.get(), job_id, result, result_code);
    return {true, L"The Agent lifecycle result was delivered."};
  } catch (const std::exception& error) {
    try { return {false, wide(error.what())}; }
    catch (...) { return {false, L"The Agent lifecycle result delivery failed."}; }
  }
}
}  // namespace ipms::agent::windows
