/**
 * @file CveQuerier.hpp
 * @brief Query front end: routes packages to the right database (OSV for
 *        kernels, the Arch Security Tracker otherwise) and normalizes both
 *        response shapes into PackageFindings.
 */

#pragma once

#include "cachy-audit/ASTClient.hpp"
#include "cachy-audit/Cvss.hpp"
#include "cachy-audit/OSVClient.hpp"
#include "cachy-audit/Package.hpp"
#include "cachy-audit/core/vercmp.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace cachy_audit {

namespace detail {
    /** @brief Exception-safe string extraction from a json object. */
    [[nodiscard]] inline std::string str_or(const json& j, const char* key,
                                            std::string fallback = {}) {
        if (const auto it = j.find(key); it != j.end() && it->is_string())
            return it->get<std::string>();
        return fallback;
    }
}  // namespace detail

/**
 * @brief Feeds installed packages to the right CVE database — OSV for kernels,
 *        the Arch Security Tracker for everything else — using batched queries,
 *        and normalizes both response shapes into PackageFindings.
 */
class CveQuerier {
  public:
    /** @brief Queries both databases; returns only packages with at least one CVE. */
    [[nodiscard]] std::vector<PackageFinding> query(const std::vector<Package>& pkgs) {
        std::vector<Package> kernel_pkgs, arch_pkgs;
        std::partition_copy(pkgs.begin(), pkgs.end(), std::back_inserter(kernel_pkgs),
                            std::back_inserter(arch_pkgs),
                            [](const Package& p) { return is_kernel_pkg(p); });

        std::vector<PackageFinding> findings = query_kernel(kernel_pkgs);
        auto arch = query_arch(arch_pkgs);
        findings.insert(findings.end(), std::make_move_iterator(arch.begin()),
                        std::make_move_iterator(arch.end()));
        return findings;
    }

  private:
    /** @brief OSV results for the kernel packages, deduplicated by CVE id. */
    [[nodiscard]] std::vector<PackageFinding>
    query_kernel(const std::vector<Package>& pkgs) {
        if (pkgs.empty()) return {};

        const auto res = m_Osv.queryBatch(pkgs);
        std::vector<PackageFinding> findings{};

        for (std::size_t i = 0; i < pkgs.size(); ++i) {
            if (!res[i].is_object()) continue;

            PackageFinding pf{.m_Package = pkgs[i]};
            std::unordered_set<std::string> seen{};
            for (const auto& v : res[i].value("vulns", json::array())) {
                auto id = canonical_id(v);
                CveFinding cve{
                    .m_Id = id,
                    .m_Summary = summarize(v),
                    .m_Source = "OSV",
                    .m_Url = reference_url(v, id),
                };
                apply_osv_severity(v, cve);
                if (seen.insert(cve.m_Id).second)
                    pf.m_Findings.push_back(std::move(cve));
            }
            if (!pf.m_Findings.empty()) findings.push_back(std::move(pf));
        }
        return findings;
    }

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
    query_arch(const std::vector<Package>& pkgs) {
        if (pkgs.empty()) return {};

        const auto res = m_Ast.queryBatch(pkgs);
        std::vector<PackageFinding> findings{};

        for (std::size_t i = 0; i < pkgs.size(); ++i) {
            if (!res[i].is_object()) continue;

            PackageFinding pf{.m_Package = pkgs[i]};
            std::unordered_set<std::string> seen{};
            for (const auto& issue : res[i].value("issues", json::array())) {
                if (detail::str_or(issue, "status") != "Vulnerable") continue;

                const auto& installed = pkgs[i].version;
                if (const auto fixed = detail::str_or(issue, "fixed");
                    !fixed.empty() && alpm::vercmp(installed, fixed) >= 0)
                    continue;
                if (const auto affected = detail::str_or(issue, "affected");
                    !affected.empty() && alpm::vercmp(installed, affected) > 0)
                    continue;

                const auto severity =
                    severity_from_string(detail::str_or(issue, "severity"));
                const auto type = detail::str_or(issue, "type");
                // NOTE: res[i]["issues"] = issue list; issue["issues"] = the CVE ids
                for (const auto& c : issue.value("issues", json::array())) {
                    if (!c.is_string()) continue;
                    CveFinding cve{
                        .m_Id = c.get<std::string>(),
                        .m_Summary = type,
                        .m_Source = "AST",
                        .m_Url = std::string{internal::AST_CVE_LINK} +
                                 c.get<std::string>(),
                        .m_Severity = severity,
                    };
                    if (seen.insert(cve.m_Id).second)
                        pf.m_Findings.push_back(std::move(cve));
                }
            }
            if (!pf.m_Findings.empty()) findings.push_back(std::move(pf));
        }
        return findings;
    }

    /** @brief Prefer the canonical CVE id over distro-specific aliases (AVG-..., etc). */
    [[nodiscard]] static std::string canonical_id(const json& vuln) {
        if (const auto it = vuln.find("aliases"); it != vuln.end() && it->is_array())
            for (const auto& alias : *it)
                if (alias.is_string()) {
                    auto id = alias.get<std::string>();
                    if (id.starts_with("CVE-")) return id;
                }
        return detail::str_or(vuln, "id", "?");
    }

    /** @brief Short description of a vuln: "summary", falling back to "details". */
    [[nodiscard]] static std::string summarize(const json& vuln) {
        if (auto summary = detail::str_or(vuln, "summary"); !summary.empty())
            return summary;
        return detail::str_or(vuln, "details");
    }

    /**
     * @brief Best link for a vuln: prefer an ADVISORY reference, then any
     *        reference, else fall back to the entry's page on osv.dev.
     */
    [[nodiscard]] static std::string reference_url(const json& vuln,
                                                   const std::string& id) {
        const auto it = vuln.find("references");
        if (it == vuln.end() || !it->is_array())
            return std::string{internal::OSV_VULN_LINK} + id;

        std::string any{};
        for (const auto& ref : *it) {
            auto url = detail::str_or(ref, "url");
            if (url.empty()) continue;
            if (detail::str_or(ref, "type") == "ADVISORY") return url;
            if (any.empty()) any = std::move(url);
        }
        return any.empty() ? std::string{internal::OSV_VULN_LINK} + id : any;
    }

    /**
     * @brief OSV carries severity as a list of CVSS vector strings, e.g.
     *        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."} — parse it,
     *        falling back to the plain severity string in "database_specific".
     */
    static void apply_osv_severity(const json& vuln, CveFinding& cve) {
        if (const auto it = vuln.find("severity"); it != vuln.end() && it->is_array())
            for (const auto& entry : *it) {
                if (detail::str_or(entry, "type") != "CVSS_V3") continue;
                try {
                    cve.m_Score =
                        cvss::base_score(detail::str_or(entry, "score"));
                    cve.m_Severity = severity_from_score(cve.m_Score);
                    return;
                } catch (const std::invalid_argument&) {
                    // malformed vector — fall through to the fallback below
                }
            }

        if (const auto it = vuln.find("database_specific");
            it != vuln.end() && it->is_object())
            cve.m_Severity =
                severity_from_string(detail::str_or(*it, "severity"));
    }

    OSVClient m_Osv{};  /**< kernel database */
    ASTClient m_Ast{};  /**< everything else */
};

}  // namespace cachy_audit
