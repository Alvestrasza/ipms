#include "ipms/agent/windows_management_journal.hpp"

#include <windows.h>
#include <sddl.h>
#include <memory>
#include <stdexcept>

namespace ipms::agent::windows {
namespace {
struct handle_closer {
  void operator()(void* handle) const {
    if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
  }
};
using file_handle = std::unique_ptr<void, handle_closer>;
struct local_closer { void operator()(void* value) const { if (value) LocalFree(value); } };
using local_memory = std::unique_ptr<void, local_closer>;

void no_reparse_ancestors(const std::filesystem::path& directory) {
  if (!directory.is_absolute()) throw std::runtime_error("Invalid journal directory.");
  for (auto current = directory; !current.empty();) {
    const auto attributes = GetFileAttributesW(current.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        !(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
      throw std::runtime_error("The management journal directory is unsafe.");
    const auto parent = current.parent_path();
    if (parent == current) break;
    current = parent;
  }
}

local_memory protect_directory(const std::filesystem::path& directory) {
  no_reparse_ancestors(directory.parent_path());
  PSECURITY_DESCRIPTOR raw = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &raw, nullptr))
    throw std::runtime_error("The management journal protection could not be prepared.");
  local_memory descriptor(raw);
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), raw, FALSE};
  if (!CreateDirectoryW(directory.c_str(), &attributes) && GetLastError() != ERROR_ALREADY_EXISTS)
    throw std::runtime_error("The management journal directory could not be created.");
  no_reparse_ancestors(directory);
  if (!SetFileSecurityW(directory.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, raw))
    throw std::runtime_error("The management journal directory could not be protected.");
  return descriptor;
}

void require_regular_handle(HANDLE handle) {
  BY_HANDLE_FILE_INFORMATION info{};
  if (!GetFileInformationByHandle(handle, &info) ||
      (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) ||
      info.nNumberOfLinks != 1)
    throw std::runtime_error("The management journal file is unsafe.");
}
}  // namespace

std::optional<hyperv_management_journal::journal> load_management_journal(
    const std::filesystem::path& directory) {
  const auto protection = protect_directory(directory);
  const auto path = directory / L"current.json";
  file_handle handle(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
  if (handle.get() == INVALID_HANDLE_VALUE) {
    if (GetLastError() == ERROR_FILE_NOT_FOUND) return std::nullopt;
    throw std::runtime_error("The management journal could not be opened.");
  }
  require_regular_handle(handle.get());
  LARGE_INTEGER size{};
  if (!GetFileSizeEx(handle.get(), &size) || size.QuadPart <= 0 || size.QuadPart > 65536)
    throw std::runtime_error("The management journal size is invalid.");
  std::string content(static_cast<std::size_t>(size.QuadPart), '\0');
  DWORD read = 0;
  if (!ReadFile(handle.get(), content.data(), static_cast<DWORD>(content.size()), &read, nullptr) || read != content.size())
    throw std::runtime_error("The management journal could not be read.");
  return hyperv_management_journal::decode(content);
}

void save_management_journal(const std::filesystem::path& directory,
                             const hyperv_management_journal::journal& record) {
  const auto content = hyperv_management_journal::encode(record);
  const auto descriptor = protect_directory(directory);
  SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor.get(), FALSE};
  const auto temporary = directory / L"current.new";
  const auto target = directory / L"current.json";
  // OPEN_ALWAYS plus validation precedes truncation: never truncate a hard link
  // or follow a junction. Only LocalSystem/local administrators can replace it.
  file_handle handle(CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, &attributes,
                                OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr));
  if (handle.get() == INVALID_HANDLE_VALUE) throw std::runtime_error("The management journal could not be written.");
  require_regular_handle(handle.get());
  if (!SetEndOfFile(handle.get())) throw std::runtime_error("The management journal could not be truncated.");
  DWORD written = 0;
  if (!WriteFile(handle.get(), content.data(), static_cast<DWORD>(content.size()), &written, nullptr) ||
      written != content.size() || !FlushFileBuffers(handle.get()))
    throw std::runtime_error("The management journal could not be flushed.");
  handle.reset();
  if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw std::runtime_error("The management journal could not be committed.");
}

void archive_prepared_management_journal(const std::filesystem::path& directory,
                                         const hyperv_management_journal::binding& identity) {
  const auto recorded = load_management_journal(directory);
  if (!recorded || recorded->identity != identity || recorded->state != hyperv_management_journal::phase::prepared)
    throw std::runtime_error("Only a matching uninvoked journal can be archived.");
  const auto current = directory / L"current.json";
  const auto archive = directory / L"last-cancelled.json";
  if (!MoveFileExW(current.c_str(), archive.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw std::runtime_error("The cancelled management journal could not be archived.");
}
}  // namespace ipms::agent::windows
