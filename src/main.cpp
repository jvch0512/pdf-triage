#include "pdf_triage.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

struct Row { int rank; std::string sev, rule, where, msg; };

static int rank_of(const std::string &s) {
    if (s == "critical") return 0;
    if (s == "high") return 1;
    if (s == "medium") return 2;
    if (s == "low") return 3;
    return 4;
}

static int usage() {
    std::fprintf(stderr, "usage: pdf-triage PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n");
    return 2;
}

static bool read_file(const fs::path &p, std::string &out) {
    std::error_code ec;
    auto sz = fs::file_size(p, ec);
    if (ec || sz > 64u * 1024 * 1024) return false;
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

int main(int argc, char **argv) {
    std::string path, fail;
    bool tsv = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--tsv") tsv = true;
        else if (a == "--fail-on") {
            if (++i >= argc) return usage();
            fail = argv[i];
            if (fail != "medium" && fail != "high" && fail != "critical") return usage();
        } else if (!a.empty() && a[0] == '-') return usage();
        else if (!path.empty()) return usage();
        else path = a;
    }
    if (path.empty()) return usage();
    std::error_code ec;
    if (!fs::exists(path, ec)) { std::fprintf(stderr, "error: no such file or directory: %s\n", path.c_str()); return 2; }

    std::vector<std::pair<std::string, fs::path>> files;
    if (fs::is_directory(path, ec)) {
        for (auto &e : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
            if (!e.is_regular_file(ec)) continue;
            std::string ext = e.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char c) { return (char)std::tolower(c); });
            if (ext != ".pdf") continue;
            files.push_back({fs::relative(e.path(), path, ec).generic_string(), e.path()});
        }
        std::sort(files.begin(), files.end());
    } else {
        files.push_back({fs::path(path).filename().string(), path});
    }

    std::vector<Row> rows;
    int pdfs = 0;
    for (auto &f : files) {
        std::string data;
        if (!read_file(f.second, data)) continue;
        pdft::Report r = pdft::analyze(data);
        if (r.is_pdf) pdfs++;
        for (auto &x : r.findings) rows.push_back({rank_of(x.sev), x.sev, x.rule, f.first, x.msg});
    }
    std::stable_sort(rows.begin(), rows.end(), [](const Row &a, const Row &b) {
        if (a.rank != b.rank) return a.rank < b.rank;
        if (a.where != b.where) return a.where < b.where;
        return a.rule < b.rule;
    });
    char head[128];
    std::snprintf(head, sizeof head, "%d PDF files, %zu findings", pdfs, rows.size());
    if (tsv) std::printf("# %s\n", head);
    else std::printf("%s\n", head);
    for (auto &r : rows) {
        if (tsv) std::printf("%s\t%s\t%s\t%s\n", r.sev.c_str(), r.rule.c_str(), r.where.c_str(), r.msg.c_str());
        else {
            std::string up = r.sev;
            std::transform(up.begin(), up.end(), up.begin(), [](unsigned char c) { return (char)std::toupper(c); });
            std::printf("%-8s %s %s\n         %s\n", up.c_str(), r.rule.c_str(), r.where.c_str(), r.msg.c_str());
        }
    }
    if (!fail.empty()) {
        int floor = rank_of(fail);
        for (auto &r : rows) if (r.rank <= floor) return 1;
    }
    return 0;
}
