#include "cachy-audit/CveQuerier.hpp"

#include "cachy-audit/Cvss.hpp"
#include "cachy-audit/core/consts.hpp"
#include "cachy-audit/core/system.hpp"
#include "cachy-audit/core/vercmp.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>
#include <unordered_set>

namespace cachy_audit {

namespace detail {
    /** @brief Exception-safe string extraction from a json object. */
    [[nodiscard]] std::string str_or(const json& j, const char* key,
                                     std::string fallback = {}) {
        if (const auto it = j.find(key); it != j.end() && it->is_string())
            return it->get<std::string>();
        return fallback;
    }
}  // namespace detail

std::vector<PackageFinding> CveQuerier::query(const std::vector<Package>& pkgs) {
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

std::vector<PackageFinding> CveQuerier::query_kernel(const std::vector<Package>& pkgs) {
    if (pkgs.empty()) return {};

    const auto res = m_Nvd.query(internal::get_kernel_version());
    std::vector<CveFinding> cves{};
    for (const auto& cve : res.value("vulns", json::array())) {
        // NVD keeps rejected entries around; they are not real vulnerabilities
        if (detail::str_or(cve, "vulnStatus") == "Rejected") continue;

        const auto id = detail::str_or(cve, "id", "?");
        CveFinding finding{
            .m_Id = id,
            .m_Summary = describe(cve),
            .m_Source = "NVD",
            .m_Url = std::string{internal::NVD_CVE_LINK} + id,
        };
        apply_nvd_metrics(cve, finding);
        cves.push_back(std::move(finding));
    }
    if (cves.empty()) return {};

    std::vector<PackageFinding> findings{};
    findings.reserve(pkgs.size());
    for (const auto& pkg : pkgs)
        findings.push_back(PackageFinding{.m_Package = pkg, .m_Findings = cves});
    return findings;
}

std::vector<PackageFinding> CveQuerier::query_arch(const std::vector<Package>& pkgs) {
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
                    .m_Url =
                        std::string{internal::AST_CVE_LINK} + c.get<std::string>(),
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

std::string CveQuerier::describe(const json& cve) {
    const auto it = cve.find("descriptions");
    if (it == cve.end() || !it->is_array()) return {};

    std::string first{};
    for (const auto& d : *it) {
        const auto value = detail::str_or(d, "value");
        if (first.empty()) first = value;
        if (detail::str_or(d, "lang") == "en") return value;
    }
    return first;
}

void CveQuerier::apply_nvd_metrics(const json& cve, CveFinding& out) {
    const auto metrics = cve.find("metrics");
    if (metrics == cve.end() || !metrics->is_object()) return;

    for (const char* key : {"cvssMetricV31", "cvssMetricV30"}) {
        const auto it = metrics->find(key);
        if (it == metrics->end() || !it->is_array() || it->empty()) continue;

        const auto data = it->front().find("cvssData");
        if (data == it->front().end()) continue;

        try {
            out.m_Score = cvss::base_score(detail::str_or(*data, "vectorString"));
            out.m_Severity = severity_from_score(out.m_Score);
            return;
        } catch (const std::invalid_argument&) {
            // malformed vector — try the next metric list
        }
    }
}

}  // namespace cachy_audit
