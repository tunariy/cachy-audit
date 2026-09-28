#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string_view>

namespace cachy_audit::internal {

inline constexpr std::string_view NVD_API_BASE{
    "https://services.nvd.nist.gov/rest/json/cves/2.0"};
inline constexpr std::string_view AST_API_LINK{
    "https://security.archlinux.org/issues/all.json"};
/** @brief CPE 2.3 prefix of the Linux kernel; the version is appended to it. */
inline constexpr std::string_view NVD_KERNEL_CPE{"cpe:2.3:o:linux:linux_kernel:"};
inline constexpr std::string_view USER_AGENT{"cachy-audit/0.1"};

/** @brief Base URLs for vulnerability pages (append the vuln/CVE id). */
inline constexpr std::string_view NVD_CVE_LINK{"https://nvd.nist.gov/vuln/detail/"};
inline constexpr std::string_view AST_CVE_LINK{"https://security.archlinux.org/"};

/** @brief Kernels that are supported by CachyOS. */
inline constexpr std::array<std::string_view, 17> KERNEL_PKGS{
    "linux",
    "linux-lts",
    "linux-zen",
    "linux-hardened",
    "linux-rt",
    "linux-cachyos",
    "linux-cachyos-bore",
    "linux-cachyos-deckify",
    "linux-cachyos-lts",
    "linux-cachyos-rc",
    "linux-cachyos-server",
    "linux-cachyos-hardened",
    "linux-cachyos-rt",
    "linux-xanmod",
    "linux-xanmod-edge",
    "linux-amd",
    "linux-nvidia-open",
};

/** @brief Numeric rank per severity name; matches the SeverityLevel enum order. */
inline const std::map<std::string_view, std::uint32_t> SEV_ORDER{
    {"Critical", 5}, {"High", 4}, {"Medium", 3}, {"Low", 2}, {"None", 1}, {"Unknown", 0}};

}  // namespace cachy_audit::internal
