#include "prx/libc/include/General.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include "SceTypes.hpp"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <stdexcept>
#include <string>
#define NOMINMAX
#include <windows.h>

extern "C" {
int APS5_VABI sceKernelStat(const char*, FileStat*);
int APS5_VABI stat_nid_postfix(const char*, FileStat*);
int APS5_VABI lstat_nid_postfix(const char*, FileStat*);
int* APS5_VABI __error_nid_postfix();
}

namespace {

constexpr int GuestEnoent = static_cast<int>(0x80020002u);
constexpr std::uint16_t GuestFormatMask = 0170000;
constexpr std::uint16_t GuestRegular = 0100000;
constexpr std::uint16_t GuestDirectory = 0040000;

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::filesystem::path Extended(const std::filesystem::path& path) {
    const auto& native = path.native();
    return native.starts_with(L"\\\\") ? L"\\\\?\\UNC\\" + native.substr(2) : L"\\\\?\\" + native;
}

FileStat Stat(const char* path) {
    FileStat stat{};
    const int result = sceKernelStat(path, &stat);
    if (result != 0) {
        std::fprintf(stderr, "sceKernelStat failed: result=0x%08x, resolved characters=%zu\n", static_cast<unsigned>(result), ResolvePath_nid_no_patch(path).native().size());
        throw std::runtime_error("sceKernelStat rejected a valid mapped long host path");
    }
    return stat;
}

void Run() {
    auto temp = std::filesystem::absolute(std::filesystem::temp_directory_path()).lexically_normal();
    if (temp.filename().empty()) temp = temp.parent_path();
    const auto root = temp / ("anyps5-stat-long-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Require(root.parent_path() == temp && root.filename().string().starts_with("anyps5-stat-long-"), "invalid fixture root");
    Require(!std::filesystem::exists(root), "fixture root already exists");
    auto deep = root;
    while (deep.native().size() < 290) deep /= std::string(40, 'd');
    Require(deep.native().starts_with(root.native() + L"\\"), "fixture escapes its root");
    struct Cleanup {
        std::filesystem::path root;
        std::filesystem::path deep;
        ~Cleanup() {
            RemovePathAlias_nid_no_patch("/long-host-stat");
            RemovePathAlias_nid_no_patch("/relative-long-host-stat");
            DeleteFileW(Extended(deep / "payload.bin").c_str());
            for (auto path = deep; ; path = path.parent_path()) {
                RemoveDirectoryW(Extended(path).c_str());
                if (path == root) break;
            }
        }
    } cleanup{root, deep};
    Require(std::filesystem::create_directories(Extended(deep)), "cannot create fixture directories");
    const auto payload = deep / "payload.bin";
    const auto handle = CreateFileW(Extended(payload).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    Require(handle != INVALID_HANDLE_VALUE, "cannot prepare long-path file");
    DWORD written = 0;
    const bool prepared = WriteFile(handle, "abcd", 4, &written, nullptr) && written == 4;
    CloseHandle(handle);
    Require(prepared, "cannot write fixture payload");
    const auto host = deep.string();
    AddPathAlias_nid_no_patch("/long-host-stat", host.c_str());
    Require(ResolvePath_nid_no_patch("/long-host-stat/payload.bin").native().size() > MAX_PATH, "fixture does not cross MAX_PATH");
    {
        const auto stat = Stat("/long-host-stat/payload.bin");
        Require((stat.st_mode & GuestFormatMask) == GuestRegular, "long-path file is not reported as a regular file");
        Require(stat.st_size == 4, "long-path file size differs");
    }
    {
        const auto stat = Stat("/long-host-stat");
        Require((stat.st_mode & GuestFormatMask) == GuestDirectory, "long-path directory is not reported as a directory");
    }
    {
        const auto stat = Stat("/long-host-stat/");
        Require((stat.st_mode & GuestFormatMask) == GuestDirectory, "long-path directory with a trailing slash is not reported as a directory");
    }
    {
        FileStat stat{};
        Require(stat_nid_postfix("/long-host-stat/payload.bin", &stat) == 0 && stat.st_size == 4, "POSIX stat rejected a valid mapped long host path");
        FileStat link{};
        Require(lstat_nid_postfix("/long-host-stat/payload.bin", &link) == 0 && link.st_size == 4 && (link.st_mode & GuestFormatMask) == GuestRegular, "POSIX lstat rejected a valid mapped long host path");
    }
    {
        FileStat stat{};
        Require(sceKernelStat("/long-host-stat/missing.bin", &stat) == GuestEnoent, "missing long-path file did not report ENOENT");
        *__error_nid_postfix() = 0;
        Require(stat_nid_postfix("/long-host-stat/missing.bin", &stat) == -1 && *__error_nid_postfix() == 2, "POSIX stat of a missing long-path file did not report ENOENT");
    }
    const auto relative = std::filesystem::relative(deep, std::filesystem::current_path()).string();
    Require(!std::filesystem::path(relative).is_absolute(), "fixture alias is not relative");
    AddPathAlias_nid_no_patch("/relative-long-host-stat", relative.c_str());
    {
        const auto stat = Stat("/relative-long-host-stat/payload.bin");
        Require((stat.st_mode & GuestFormatMask) == GuestRegular && stat.st_size == 4, "relative long-path file stat differs");
    }
    std::puts("long host path stat file/directory/trailing-slash/posix/lstat/missing/relative checks passed");
}

}

int main() {
    try { Run(); }
    catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
    return 0;
}
