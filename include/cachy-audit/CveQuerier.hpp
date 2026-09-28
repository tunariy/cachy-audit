#pragma once

#include "cachy-audit/ASTClient.hpp"
#include "cachy-audit/NVDClient.hpp"
#include "cachy-audit/Package.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace cachy_audit {

/**
 * @brief Feeds installed packages to the right CVE database — NVD for kernels,
 *        the Arch Security Tracker for everything else — and normalizes both
 *        response shapes into PackageFindings.
 */
class CveQuerier {
  public:
    /** @brief Queries both databases; returns only packages with at least one CVE. */
    [[nodiscard]] std::vector<PackageFinding> query(const std::vector<Package>& pkgs);

  private:
    /** @brief All CVEs affecting one kernel version. */
    [[nodiscard]] std::vector<CveFinding> kernel_cves(const std::string& version);

    /**
     * @brief AST results for the non-kernel packages, deduplicated by CVE id.
     *
     * AST records the package version that was current when an issue was
     * filed and rarely updates it, while CachyOS versions routinely run
     * ahead of Arch's — issues whose "affected" version is older than the
     * installed version (or whose "fixed" version is already installed) are
     * treated as stale and dropped.
     */
    [[nodiscard]] std::vector<PackageFinding>
    query_arch(const std::vector<Package>& pkgs);

    /** @brief English description of an NVD CVE entry. */
    [[nodiscard]] static std::string describe(const json& cve);

    /**
     * @brief Whether NVD marks the kernel itself as vulnerable in this CVE —
     *        userland CVEs list the kernel as a non-vulnerable "runs on"
     *        platform, which must not count.
     */
    [[nodiscard]] static bool affects_kernel(const json& cve, std::string_view version);

    /**
     * @brief Whether a version satisfies a cpeMatch entry's version range.
     *        Ranges without an upper bound do not count — NVD rarely goes back
     *        to close them once the kernel is patched, so they only say the
     *        CVE predates the record, not that the version is still affected.
     */
    [[nodiscard]] static bool version_in_range(const json& match, std::string_view version);

    /**
     * @brief NVD carries CVSS metrics per version; takes the first v3.x
     *        vector (v3.1 preferred) and computes the base score from it.
     */
    static void apply_nvd_metrics(const json& cve, CveFinding& out);

    NVDClient m_Nvd{}; /**< kernel database */
    ASTClient m_Ast{}; /**< everything else */
};

}  // namespace cachy_audit
