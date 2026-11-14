CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2

build:
	$(CXX) $(CXXFLAGS) -o pdf-triage src/pdf_triage.cpp src/main.cpp

test: build
	$(CXX) $(CXXFLAGS) -g -fsanitize=address,undefined -o tests/run tests/test.cpp src/pdf_triage.cpp && ./tests/run

sample: build
	mkdir -p docs site
	./pdf-triage examples > docs/sample-output.txt; true
	./pdf-triage examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "pdf-triage" "Static triage of PDF files: JavaScript, launch actions, embedded files, name obfuscation, incremental updates. C++." "Hand-written minimal PDFs, no real malware."
