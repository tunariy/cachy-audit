#pragma once

#include "cachy-audit/ASTClient.hpp"
#include "cachy-audit/NVDClient.hpp"
#include "cachy-audit/Package.hpp"

#include <string>
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
    /**
     * @brief NVD results for the running kernel, shared by every installed
     *        kernel package.
     */
    [[nodiscard]] std::vector<PackageFinding>
    query_kernel(const std::vector<Package>& pkgs);

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
     * @brief NVD carries CVSS metrics per version; takes the first v3.x
     *        vector (v3.1 preferred) and computes the base score from it.
     */
    static void apply_nvd_metrics(const json& cve, CveFinding& out);

    NVDClient m_Nvd{}; /**< kernel database */
    ASTClient m_Ast{}; /**< everything else */
};

}  // namespace cachy_audit
