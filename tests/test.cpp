#include "../src/pdf_triage.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>

static int passed = 0, failed = 0;
#define CHECK(c) do { if (c) passed++; else { failed++; std::printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static bool has(const pdft::Report &r, const char *rule) {
    for (auto &f : r.findings) if (f.rule == rule) return true;
    return false;
}
static std::string sev(const pdft::Report &r, const char *rule) {
    for (auto &f : r.findings) if (f.rule == rule) return f.sev;
    return "";
}
static std::string pdf(const std::string &body, const std::string &tail = "%%EOF\n") { return "%PDF-1.4\n" + body + tail; }
static int exit_of(const char *cmd) { int s = std::system(cmd); return WIFEXITED(s) ? WEXITSTATUS(s) : -1; }

static unsigned long long rng = 88172645463325252ULL;
static unsigned next() { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)(rng >> 11); }

int main() {
    using pdft::analyze;
    // clean file
    auto r = analyze(pdf("1 0 obj\n<< /Type /Catalog >>\nendobj\n"));
    CHECK(r.is_pdf); CHECK(r.findings.empty());

    // not a PDF
    r = analyze("hello"); CHECK(!r.is_pdf); CHECK(has(r, "PDF000"));
    r = analyze(""); CHECK(!r.is_pdf); CHECK(has(r, "PDF000"));
    r = analyze(std::string(2000, 'x') + "%PDF-1.4"); CHECK(!r.is_pdf);       // header too late
    r = analyze(std::string(100, ' ') + "%PDF-1.7\n"); CHECK(r.is_pdf);      // header within 1024 bytes

    // javascript
    r = analyze(pdf("<< /S /JavaScript /JS (x) >>"));
    CHECK(has(r, "PDF001")); CHECK(sev(r, "PDF001") == "high");
    r = analyze(pdf("<< /JS (x) >>")); CHECK(has(r, "PDF001"));
    r = analyze(pdf("<< /JSON 1 >>")); CHECK(!has(r, "PDF001"));              // prefix must not match

    // launch
    r = analyze(pdf("<< /S /Launch /F (a) >>")); CHECK(has(r, "PDF002")); CHECK(sev(r, "PDF002") == "high");

    // open action: medium alone, high with script
    r = analyze(pdf("<< /OpenAction 3 0 R >>")); CHECK(has(r, "PDF003")); CHECK(sev(r, "PDF003") == "medium");
    r = analyze(pdf("<< /OpenAction 3 0 R /JS (x) >>")); CHECK(sev(r, "PDF003") == "high");
    r = analyze(pdf("<< /AA << /O 1 0 R >> /S /Launch >>")); CHECK(sev(r, "PDF003") == "high");
    r = analyze(pdf("<< /AA << /O 1 0 R >> >>")); CHECK(sev(r, "PDF003") == "medium");

    // embedded, uri, submit
    r = analyze(pdf("<< /Type /EmbeddedFile >>")); CHECK(has(r, "PDF004")); CHECK(sev(r, "PDF004") == "medium");
    r = analyze(pdf("<< /S /URI /URI (http://x.test) >>")); CHECK(has(r, "PDF005"));
    r = analyze(pdf("<< /S /SubmitForm >>")); CHECK(has(r, "PDF005"));

    // obfuscated names
    r = analyze(pdf("<< /S /J#61vaScript >>"));
    CHECK(has(r, "PDF001")); CHECK(has(r, "PDF006")); CHECK(sev(r, "PDF006") == "high");
    r = analyze(pdf("<< /#4Aava#53cript >>")); CHECK(has(r, "PDF006"));
    r = analyze(pdf("<< /Some#20Name 1 >>")); CHECK(!has(r, "PDF006"));         // harmless escape
    r = analyze(pdf("<< /Launch#2 >>")); CHECK(!has(r, "PDF006"));              // malformed escape is not decoded

    // legacy surface
    r = analyze(pdf("<< /XFA 1 0 R >>")); CHECK(has(r, "PDF007"));
    r = analyze(pdf("<< /Subtype /RichMedia >>")); CHECK(has(r, "PDF007"));
    r = analyze(pdf("<< /Subtype /3D >>")); CHECK(has(r, "PDF007"));

    // structure
    r = analyze(pdf("<< /Encrypt 5 0 R >>")); CHECK(has(r, "PDF008")); CHECK(sev(r, "PDF008") == "low");
    r = analyze(pdf("a\n%%EOF\nb\n")); CHECK(has(r, "PDF008"));                  // two EOF markers
    r = analyze(pdf("a\n", "%%EOF\nMZ")); CHECK(has(r, "PDF008"));                // trailing data
    r = analyze(pdf("a\n", "%%EOF\n\r\n  ")); CHECK(!has(r, "PDF008"));          // trailing whitespace only
    r = analyze(pdf("<< /Type /ObjStm >>")); CHECK(has(r, "PDF009"));

    // skipping: strings, comments, streams do not count
    r = analyze(pdf("(this mentions /JavaScript and /Launch)")); CHECK(r.findings.empty());
    r = analyze(pdf("(nested (/JavaScript) still string)")); CHECK(r.findings.empty());
    r = analyze(pdf("(escaped \\) /Launch still inside)")); CHECK(r.findings.empty());
    r = analyze(pdf("% /JavaScript in a comment\n1 0 obj\n")); CHECK(r.findings.empty());
    r = analyze(pdf("<2F4A617661536372697074>")); CHECK(r.findings.empty());      // hex string is not a name
    r = analyze(pdf("<< /Length 20 >>\nstream\n/JavaScript /Launch\nendstream\n")); CHECK(r.findings.empty());
    r = analyze(pdf("<< >>\nstream\r\n/Launch\r\nendstream\n/JS ")); CHECK(has(r, "PDF001") && !has(r, "PDF002"));
    r = analyze(pdf("<< >>\nstream\n/Launch")); CHECK(r.findings.empty());        // unterminated stream swallows the rest
    r = analyze(pdf("<< /S /JavaScript >>\nstream\nx\nendstream\n<< /S /Launch >>")); CHECK(has(r, "PDF001") && has(r, "PDF002"));

    // hostile input never crashes (ASan and UBSan are on)
    r = analyze(pdf("(unterminated string /JavaScript")); CHECK(r.is_pdf);
    r = analyze(pdf("<unterminated hex")); CHECK(r.is_pdf);
    r = analyze(pdf("/" + std::string(100000, 'A'))); CHECK(r.is_pdf);
    r = analyze(pdf(std::string(50000, '('))); CHECK(r.is_pdf);
    r = analyze(pdf(std::string(50000, '\\'))); CHECK(r.is_pdf);
    r = analyze(pdf("/J#")); CHECK(r.is_pdf);
    r = analyze(pdf("/J#6")); CHECK(r.is_pdf);
    r = analyze(std::string("%PDF-\0\0\0/\0JS", 12)); CHECK(r.is_pdf);

    // fuzz: random mutations of a rich document
    std::string base = pdf("1 0 obj\n<< /Type /Catalog /OpenAction 3 0 R /Names << /EmbeddedFiles 5 0 R >> >>\nendobj\n"
                           "3 0 obj\n<< /S /J#61vaScript /JS (a(b)\\)c) >>\nendobj\n"
                           "5 0 obj\n<< /Length 4 >>\nstream\nabcd\nendstream\nendobj\n<4A53> /URI /Launch\n");
    for (int i = 0; i < 3000; i++) {
        std::string m = base;
        int muts = 1 + (int)(next() % 6);
        for (int k = 0; k < muts; k++) {
            size_t pos = next() % m.size();
            switch (next() % 3) {
                case 0: m[pos] = (char)next(); break;
                case 1: m.erase(pos, 1 + next() % 8); if (m.empty()) m = "%PDF-"; break;
                default: m.insert(pos, std::string(1 + next() % 4, "()<>/#\\%s"[next() % 9])); break;
            }
        }
        auto q = analyze(m);
        (void)q;
    }
    CHECK(true);

    // CLI
    CHECK(exit_of("./pdf-triage examples >/dev/null") == 0);
    CHECK(exit_of("./pdf-triage examples --fail-on high >/dev/null") == 1);
    CHECK(exit_of("./pdf-triage examples/clean.pdf --fail-on medium >/dev/null") == 0);
    CHECK(exit_of("./pdf-triage examples/launch.pdf --fail-on high >/dev/null") == 1);
    CHECK(exit_of("./pdf-triage /no/such/path >/dev/null 2>&1") == 2);
    CHECK(exit_of("./pdf-triage >/dev/null 2>&1") == 2);
    CHECK(exit_of("./pdf-triage examples --bogus >/dev/null 2>&1") == 2);
    CHECK(exit_of("./pdf-triage examples --fail-on nope >/dev/null 2>&1") == 2);
    CHECK(exit_of("./pdf-triage examples --tsv | head -1 | grep -q '^# '") == 0);

    std::printf("%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
