#include "cachy-audit/CveQuerier.hpp"

#include "cachy-audit/Cvss.hpp"
#include "cachy-audit/core/consts.hpp"
#include "cachy-audit/core/util.hpp"
#include "cachy-audit/core/vercmp.hpp"

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <exception>
#include <iterator>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
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

    /** @brief Mailbox the kernel thread pushes findings into. */
    struct KernelChannel {
        std::mutex mtx{};
        std::condition_variable cv{};
        std::deque<PackageFinding> ready{};
        std::exception_ptr error{};
        std::size_t pending{0};
    };
    const auto channel = std::make_shared<KernelChannel>();
    channel->pending = kernel_pkgs.size();

    // NVD queries are rate-limited, so they run on a detached thread while the
    // AST lookup happens here; findings are drained from the channel as they arrive
    std::jthread{[this, channel, kernel_pkgs = std::move(kernel_pkgs)] {
        std::unordered_map<std::string, std::vector<CveFinding>> cache{};
        for (const auto& pkg : kernel_pkgs) {
            PackageFinding pf{.m_Package = pkg};
            try {
                auto version = split_upstream_version(pkg.version);
                auto [it, inserted] = cache.try_emplace(version);
                if (inserted) it->second = kernel_cves(version);
                pf.m_Findings = it->second;
            } catch (...) {
                std::lock_guard lock{channel->mtx};
                channel->error = std::current_exception();
                channel->pending = 0;
                channel->cv.notify_all();
                return;
            }
            {
                std::lock_guard lock{channel->mtx};
                channel->ready.push_back(std::move(pf));
                --channel->pending;
            }
            channel->cv.notify_one();
        }
    }}.detach();

    std::vector<PackageFinding> findings = query_arch(arch_pkgs);

    for (;;) {
        std::unique_lock lock{channel->mtx};
        channel->cv.wait(lock,
                         [&] { return !channel->ready.empty() || channel->pending == 0; });
        while (!channel->ready.empty()) {
            auto pf = std::move(channel->ready.front());
            channel->ready.pop_front();
            if (!pf.m_Findings.empty()) findings.push_back(std::move(pf));
        }
        if (channel->pending == 0) {
            if (channel->error) std::rethrow_exception(channel->error);
            break;
        }
    }
    return findings;
}

std::vector<CveFinding> CveQuerier::kernel_cves(const std::string& version) {
    const auto res = m_Nvd.query(version);
    std::vector<CveFinding> cves{};
    for (const auto& cve : res.value("vulns", json::array())) {
        // NVD keeps rejected entries around; they are not real vulnerabilities
        if (detail::str_or(cve, "vulnStatus") == "Rejected") continue;
        if (!affects_kernel(cve, version)) continue;

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
    return cves;
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

bool CveQuerier::affects_kernel(const json& cve, std::string_view version) {
    const auto configs = cve.find("configurations");
    if (configs == cve.end() || !configs->is_array()) return false;

    for (const auto& config : *configs)
        for (const auto& node : config.value("nodes", json::array()))
            for (const auto& match : node.value("cpeMatch", json::array())) {
                if (!match.value("vulnerable", false)) continue;
                if (!detail::str_or(match, "criteria")
                         .starts_with(internal::NVD_KERNEL_CPE))
                    continue;
                if (version_in_range(match, version)) return true;
            }
    return false;
}

bool CveQuerier::version_in_range(const json& match, std::string_view version) {
    // the version field of the CPE itself may already be an exact match
    const auto criteria = detail::str_or(match, "criteria");
    std::string_view exact{criteria};
    exact.remove_prefix(internal::NVD_KERNEL_CPE.size());
    exact = exact.substr(0, exact.find(':'));
    if (exact != "*" && exact != "-" && !exact.empty() &&
        alpm::vercmp(version, exact) == 0)
        return true;

    bool has_end = false;
    const auto within = [&](const char* key, auto out_of_range, bool is_end) {
        const auto bound = detail::str_or(match, key);
        if (bound.empty()) return true;
        has_end |= is_end;
        return !out_of_range(alpm::vercmp(version, bound));
    };
    if (!within("versionStartIncluding", [](int c) { return c < 0; }, false) ||
        !within("versionStartExcluding", [](int c) { return c <= 0; }, false) ||
        !within("versionEndIncluding", [](int c) { return c > 0; }, true) ||
        !within("versionEndExcluding", [](int c) { return c >= 0; }, true))
        return false;

    return has_end;
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
