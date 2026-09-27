/**
 * @file Package.hpp
 * @brief Core data model: packages, CVE findings and severity levels.
 */

#pragma once

#include <cachy-audit/core/consts.hpp>
#include <cachy-audit/core/system.hpp>
#include <cachy-audit/core/util.hpp>

#include "nlohmann/json.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cachy_audit {

using json = nlohmann::json;

/** @brief Severity ranking, ordered from least to most severe. */
enum class SeverityLevel : std::uint8_t { Unknown, None, Low, Medium, High, Critical };

/**
 * @brief Maps a CVSS base score to a severity using the official rating
 *        bands; negative scores mean Unknown.
 */
[[nodiscard]] inline SeverityLevel severity_from_score(float score) noexcept {
    if (score < 0.0F) return SeverityLevel::Unknown;
    if (score == 0.0F) return SeverityLevel::None;
    if (score < 4.0F) return SeverityLevel::Low;
    if (score < 7.0F) return SeverityLevel::Medium;
    if (score < 9.0F) return SeverityLevel::High;
    return SeverityLevel::Critical;
}

/** @brief Parses a severity name (case-insensitive), e.g. "High"; Unknown if unrecognized. */
[[nodiscard]] inline SeverityLevel severity_from_string(std::string_view s) noexcept {
    for (const auto& [name, order] : internal::SEV_ORDER)
        if (name.size() == s.size() &&
            std::equal(name.begin(), name.end(), s.begin(), [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) ==
                       std::tolower(static_cast<unsigned char>(b));
            }))
            return static_cast<SeverityLevel>(order);
    return SeverityLevel::Unknown;
}

/** @brief Human-readable name of a severity level, e.g. "Critical". */
[[nodiscard]] inline std::string_view to_string(SeverityLevel sev) noexcept {
    switch (sev) {
        case SeverityLevel::Critical: return "Critical";
        case SeverityLevel::High: return "High";
        case SeverityLevel::Medium: return "Medium";
        case SeverityLevel::Low: return "Low";
        case SeverityLevel::None: return "None";
        case SeverityLevel::Unknown: return "Unknown";
    }
    return "Unknown";
}

/** @brief An installed package as reported by pacman. */
struct Package {
    std::string name;
    std::string version;  /**< full version, [epoch:]upstream[-pkgrel] */
};

/** @brief A single CVE affecting a package. */
struct CveFinding {
    std::string m_Id;       /**< canonical CVE id, or the database-specific id */
    std::string m_Summary;
    std::string m_Source;   /**< database the finding came from ("OSV" / "AST") */
    std::string m_Url;      /**< link to the CVE database entry */
    float m_Score{-1.0F};   /**< CVSS base score; negative when unknown */
    SeverityLevel m_Severity{SeverityLevel::Unknown};
};

/** @brief A package together with every CVE found for it. */
struct PackageFinding {
    Package m_Package;
    std::vector<CveFinding> m_Findings;
};

/** @brief Whether the package is one of the supported CachyOS kernels. */
[[nodiscard]] inline bool is_kernel_pkg(std::string_view name) noexcept {
    return std::ranges::find(internal::KERNEL_PKGS, name) != internal::KERNEL_PKGS.end();
}

/** @brief Convenience overload taking a Package. */
[[nodiscard]] inline bool is_kernel_pkg(const Package& pkg) noexcept {
    return is_kernel_pkg(pkg.name);
}

/**
 * @brief OSV query payload for a package; kernels map to the "Kernel"/"Linux"
 *        ecosystem with the running kernel's version.
 */
inline nlohmann::json payload(const Package& p) {
    if (is_kernel_pkg(p)) {
        return {{"package",
                 {{"name", std::string{internal::KERNEL_OSV_NAME}},
                  {"ecosystem", std::string{internal::KERNEL_ECOSYSTEM}}}},
                {"version", internal::get_kernel_version()}};
    }
    return {{"package",
             {{"name", p.name}, {"ecosystem", std::string{internal::ARCH_ECOSYSTEM}}}},
            {"version", split_upstream_version(p.version)}};
}

}  // namespace cachy_audit
