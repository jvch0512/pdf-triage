#ifndef PDF_TRIAGE_HPP
#define PDF_TRIAGE_HPP
#include <string>
#include <vector>

namespace pdft {

struct Finding {
    std::string sev;   // high, medium, low, info
    std::string rule;  // PDF000..PDF009
    std::string msg;
};

struct Report {
    bool is_pdf = false;
    std::vector<Finding> findings;
};

// Never throws on any input. data may be arbitrary bytes.
Report analyze(const std::string &data);

}  // namespace pdft
#endif
