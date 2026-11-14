#include "pdf_triage.hpp"
#include <cctype>
#include <map>
#include <set>

namespace pdft {
namespace {

bool is_ws(unsigned char c) { return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32; }
bool is_delim(unsigned char c) {
    return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
}
bool is_regular(unsigned char c) { return !is_ws(c) && !is_delim(c); }
int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

struct Scan {
    std::map<std::string, int> names;   // decoded name -> count
    std::set<std::string> escaped;      // decoded names that were written with #xx
    int eof_count = 0;
    bool trailing = false;
};

size_t find_from(const std::string &d, const char *needle, size_t from) {
    return d.find(needle, from);
}

Scan scan(const std::string &d) {
    Scan s;
    const size_t n = d.size();
    size_t i = 0;
    while (i < n) {
        unsigned char c = (unsigned char)d[i];
        if (c == '%') {
            size_t e = i;
            while (e < n && d[e] != '\n' && d[e] != '\r') e++;
            if (d.compare(i, 5, "%%EOF") == 0) s.eof_count++;
            i = e;
        } else if (c == '(') {  // literal string, nested parentheses, backslash escapes
            int depth = 1;
            i++;
            while (i < n && depth > 0) {
                if (d[i] == '\\') i += 2;
                else {
                    if (d[i] == '(') depth++;
                    else if (d[i] == ')') depth--;
                    i++;
                }
            }
        } else if (c == '<') {
            if (i + 1 < n && d[i + 1] == '<') i += 2;
            else {  // hex string
                while (i < n && d[i] != '>') i++;
                if (i < n) i++;
            }
        } else if (c == '/') {
            size_t j = i + 1;
            std::string raw;
            while (j < n && is_regular((unsigned char)d[j]) && raw.size() < 256) raw += d[j++];
            std::string dec;
            bool esc = false;
            for (size_t k = 0; k < raw.size(); k++) {
                if (raw[k] == '#' && k + 2 < raw.size() && hexval((unsigned char)raw[k + 1]) >= 0 && hexval((unsigned char)raw[k + 2]) >= 0) {
                    dec += (char)(hexval((unsigned char)raw[k + 1]) * 16 + hexval((unsigned char)raw[k + 2]));
                    k += 2;
                    esc = true;
                } else dec += raw[k];
            }
            s.names[dec]++;
            if (esc) s.escaped.insert(dec);
            i = j;
        } else if (is_regular(c)) {
            size_t j = i;
            while (j < n && is_regular((unsigned char)d[j]) && j - i < 64) j++;
            if (j - i == 6 && d.compare(i, 6, "stream") == 0) {
                size_t k = j;
                if (k < n && d[k] == '\r') k++;
                if (k < n && d[k] == '\n') k++;
                size_t e = find_from(d, "endstream", k);
                i = (e == std::string::npos) ? n : e;
            } else i = j;
        } else i++;
    }
    // data after the last %%EOF that is not just whitespace
    size_t last = d.rfind("%%EOF");
    if (last != std::string::npos) {
        for (size_t k = last + 5; k < n; k++)
            if (!is_ws((unsigned char)d[k])) { s.trailing = true; break; }
    }
    return s;
}

int count(const Scan &s, const char *name) {
    auto it = s.names.find(name);
    return it == s.names.end() ? 0 : it->second;
}

}  // namespace

Report analyze(const std::string &data) {
    Report r;
    size_t head = data.substr(0, 1024).find("%PDF-");
    if (head == std::string::npos) {
        r.findings.push_back({"info", "PDF000", "not a PDF (no %PDF- header in the first 1024 bytes)"});
        return r;
    }
    r.is_pdf = true;
    Scan s = scan(data);
    auto add = [&](const char *sev, const char *rule, const std::string &msg) { r.findings.push_back({sev, rule, msg}); };

    int js = count(s, "JavaScript") + count(s, "JS");
    int launch = count(s, "Launch");
    int openaction = count(s, "OpenAction") + count(s, "AA");
    if (js) add("high", "PDF001", "JavaScript present (" + std::to_string(js) + " reference(s)): script runs inside the viewer");
    if (launch) add("high", "PDF002", "Launch action present (" + std::to_string(launch) + "): can start a program or open a file");
    if (openaction) {
        bool bad = js || launch;
        add(bad ? "high" : "medium", "PDF003",
            std::string("automatic action on open or on events (") + std::to_string(openaction) + ")" + (bad ? ", combined with script or launch" : ""));
    }
    int emb = count(s, "EmbeddedFile");
    if (emb) add("medium", "PDF004", "embedded file(s): " + std::to_string(emb) + ", extract and triage them separately");
    int uri = count(s, "URI"), submit = count(s, "SubmitForm");
    if (uri || submit) {
        std::string m;
        if (uri) m += std::to_string(uri) + " URI reference(s)";
        if (submit) m += std::string(m.empty() ? "" : ", ") + "form submission (" + std::to_string(submit) + ")";
        add("medium", "PDF005", m + ": check destinations against threat intelligence");
    }
    static const char *risky[] = {"JavaScript", "JS", "Launch", "OpenAction", "AA", "EmbeddedFile", "URI", "SubmitForm", "XFA", "RichMedia", "GoToR", "ImportData"};
    std::string hidden;
    for (const char *k : risky)
        if (s.escaped.count(k)) hidden += std::string(hidden.empty() ? "" : ", ") + "/" + k;
    if (!hidden.empty()) add("high", "PDF006", "names written with #xx escapes to avoid simple scanners: " + hidden);
    std::string legacy;
    for (const char *k : {"XFA", "RichMedia", "3D"})
        if (count(s, k)) legacy += std::string(legacy.empty() ? "" : ", ") + "/" + k;
    if (!legacy.empty()) add("medium", "PDF007", "legacy viewer attack surface: " + legacy);
    std::string odd;
    if (count(s, "Encrypt")) odd += "encrypted";
    if (s.eof_count > 1) odd += std::string(odd.empty() ? "" : "; ") + std::to_string(s.eof_count) + " %%EOF markers (incremental updates)";
    if (s.trailing) odd += std::string(odd.empty() ? "" : "; ") + "data after the last %%EOF";
    if (!odd.empty()) add("low", "PDF008", odd);
    int objstm = count(s, "ObjStm");
    if (objstm) add("low", "PDF009", "object streams (" + std::to_string(objstm) + "): objects inside compressed streams are not inspected by this tool");
    return r;
}

}  // namespace pdft
