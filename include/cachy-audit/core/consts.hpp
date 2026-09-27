/**
 * @file consts.hpp
 * @brief API endpoints, ecosystem names and lookup tables shared by the clients.
 */

#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string_view>

namespace cachy_audit::internal {

inline constexpr std::string_view OSV_API_BASE{"https://api.osv.dev/v1/query"};
inline constexpr std::string_view OSV_API_BATCH{"https://api.osv.dev/v1/querybatch"};
inline constexpr std::string_view AST_API_LINK{
    "https://security.archlinux.org/issues/all.json"};
inline constexpr std::string_view ARCH_ECOSYSTEM{"Arch Linux"};
inline constexpr std::string_view KERNEL_ECOSYSTEM{"Linux"};
inline constexpr std::string_view KERNEL_OSV_NAME{"Kernel"};
inline constexpr std::string_view USER_AGENT{"cachy-audit/0.1"};

/** @brief Base URLs for vulnerability pages (append the vuln/CVE id). */
inline constexpr std::string_view OSV_VULN_LINK{"https://osv.dev/vulnerability/"};
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
    {"Critical", 5}, {"High", 4}, {"Medium", 3},
    {"Low", 2},      {"None", 1}, {"Unknown", 0}};

}  // namespace cachy_audit::internal
