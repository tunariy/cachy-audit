#include "cachy-audit/Reporter.hpp"

#include "cachy-audit/core/color.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <ostream>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

namespace cachy_audit {

namespace detail {

    [[nodiscard]] std::string upper(std::string_view s) {
        std::string out{s};
        std::ranges::transform(out, out.begin(), [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        });
        return out;
    }

    [[nodiscard]] std::string lower(std::string_view s) {
        std::string out{s};
        std::ranges::transform(out, out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    /** @brief Flatten newlines and cap the length so one CVE always fits on one line. */
    [[nodiscard]] std::string tidy_summary(std::string text) {
        std::ranges::replace(text, '\n', ' ');
        constexpr std::size_t max_len = 90;
        if (text.size() > max_len) {
            text.resize(max_len);
            text += "…";
        }
        return text;
    }

}  // namespace detail

void print_report(std::ostream& os, std::vector<PackageFinding> findings,
                  std::size_t packages_scanned, bool color) {
    const auto paint = [color](std::string_view code, const std::string& text) {
        if (!color || code.empty()) return text;
        return std::string{code} + text + std::string{term::RESET};
    };

    const auto rank = [](const PackageFinding& f) {
        if (f.m_Findings.empty()) return std::pair{0, -1.0F};
        return std::ranges::max(
            f.m_Findings | std::views::transform([](const CveFinding& c) {
                return std::pair{static_cast<int>(c.m_Severity), c.m_Score};
            }));
    };
    std::ranges::sort(findings, [&](const auto& a, const auto& b) {
        const auto ra = rank(a), rb = rank(b);
        return ra != rb ? ra > rb : a.m_Package.name < b.m_Package.name;
    });

    std::array<std::size_t, 6> counts{};  // indexed by SeverityLevel value
    std::size_t total_cves = 0;

    for (auto& pf : findings) {
        std::ranges::sort(pf.m_Findings, [](const CveFinding& a, const CveFinding& b) {
            return a.m_Score != b.m_Score ? a.m_Score > b.m_Score : a.m_Id < b.m_Id;
        });

        const auto n = pf.m_Findings.size();
        os << paint(term::BOLD, pf.m_Package.name) << ' '
           << paint(term::DIM, pf.m_Package.version) << ' '
           << paint(term::DIM, "(" + std::to_string(n) + " CVE" + (n == 1 ? "" : "s") +
                                   " · " + pf.m_Findings.front().m_Source + ")")
           << '\n';

        for (const auto& cve : pf.m_Findings) {
            ++counts[static_cast<std::size_t>(cve.m_Severity)];
            ++total_cves;

            std::string badge = "[" + detail::upper(to_string(cve.m_Severity)) + "]";
            badge.resize(sizeof "[CRITICAL]" - 1, ' ');

            std::array<char, 8> score{};
            if (cve.m_Score >= 0.0F)
                std::snprintf(score.data(), score.size(), "%.1f",
                              static_cast<double>(cve.m_Score));
            else
                std::snprintf(score.data(), score.size(), "%s", " - ");

            os << "  " << paint(term::severity_color(cve.m_Severity, color), badge) << ' '
               << score.data() << "  "
               << term::hyperlink(cve.m_Url, paint(term::BOLD, cve.m_Id), color) << "  "
               << paint(term::DIM, detail::tidy_summary(cve.m_Summary));
            if (!color && !cve.m_Url.empty()) os << " <" << cve.m_Url << '>';
            os << '\n';
        }
        os << '\n';
    }

    if (findings.empty()) {
        os << paint(term::GREEN, "No known vulnerabilities found") << " ("
           << packages_scanned << " packages scanned)\n";
        return;
    }

    os << paint(term::BOLD, "Summary") << ": " << packages_scanned
       << " packages scanned, " << findings.size() << " vulnerable, " << total_cves
       << " CVEs";
    for (auto sev : {SeverityLevel::Critical, SeverityLevel::High, SeverityLevel::Medium,
                     SeverityLevel::Low, SeverityLevel::None, SeverityLevel::Unknown}) {
        if (const auto n = counts[static_cast<std::size_t>(sev)]; n > 0)
            os << ", "
               << paint(term::severity_color(sev, color),
                        std::to_string(n) + ' ' + detail::lower(to_string(sev)));
    }
    os << '\n';
}

}  // namespace cachy_audit
