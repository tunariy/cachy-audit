#include "cachy-audit/ASTClient.hpp"

#include "cachy-audit/core/consts.hpp"

namespace cachy_audit {

json ASTClient::queryBatch(const std::vector<Package>& pkgs) {
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

void ASTClient::ensure_dump() {
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

}  // namespace cachy_audit
