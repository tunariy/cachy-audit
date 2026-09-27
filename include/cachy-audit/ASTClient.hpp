/**
 * @file ASTClient.hpp
 * @brief Client for the Arch Security Tracker (security.archlinux.org).
 *        Downloads the full issue dump once and answers queries locally.
 */

#pragma once

#include "cachy-audit/Package.hpp"
#include "cachy-audit/core/consts.hpp"
#include "cachy-audit/core/curl.hpp"
#include "cachy-audit/core/util.hpp"

#include "nlohmann/json.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace cachy_audit {

using json = nlohmann::json;

/** @brief Queries the Arch Security Tracker for package issues. */
class ASTClient {
  public:
    /**
     * @brief Looks packages up in the issue dump (downloaded lazily on first call).
     * @return json array parallel to pkgs; an element is either null (no
     *         issues) or an object with an "issues" array of AST issue entries
     */
    [[nodiscard]] json queryBatch(const std::vector<Package>& pkgs) {
        ensure_dump();

        json results = json::array();
        for (const auto& p : pkgs) {
            if (auto it = m_Index.find(p.name);
                it != m_Index.end() && !it->second.empty())
                results.push_back(json{{"issues", it->second}});
            else
                results.push_back(nullptr);
        }
        return results;
    }

  private:
    /** @brief Downloads and indexes the issue dump if that has not happened yet. */
    void ensure_dump() {
        if (!m_Dump.empty()) return;

        network::Slist headers{};
        headers.append("User-Agent: " + std::string{internal::USER_AGENT});
        std::string post_fields;
        m_Dump = json::parse(m_Curl.query(std::string{internal::AST_API_LINK},
                                          headers.get(), post_fields));

        if (m_Dump.is_object()) {  // legacy {"pkg": [issues]} shape
            for (auto& [pkg, issues] : m_Dump.items())
                m_Index[pkg] = issues;
        } else if (m_Dump.is_array()) {  // /issues/all.json: [{...issue, "packages":
                                         // [...]}]
            for (auto& issue : m_Dump)
                for (const auto& pkg : issue.value("packages", json::array()))
                    m_Index[pkg].push_back(issue);
        }
    }

    network::Curl m_Curl{};
    json m_Dump{};
    std::unordered_map<std::string, json> m_Index{};  /**< package -> issues */
};

}  // namespace cachy_audit
