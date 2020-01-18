BINARIES := omegajail sigsys-tracer stdio-mux java-compile
POLICIES := policies/gcc.bpf policies/cpp.bpf policies/ghc.bpf policies/hs.bpf \
            policies/javac.bpf policies/java.bpf policies/fpc.bpf policies/pas.bpf \
            policies/pyc.bpf policies/py.bpf policies/ruby.bpf policies/lua.bpf \
            policies/csc.bpf policies/cs.bpf policies/js.bpf policies/karel.bpf \
            policies/cpp-asan.bpf policies/clang.bpf

MINIJAIL_SOURCE_FILES := $(addprefix minijail/,\
	$(cd minijail && git ls-tree --name-only HEAD -- *.c *.c))
MINIJAIL_CORE_OBJECT_FILES := $(addprefix minijail/,$(patsubst %.o,%.pic.o,\
	libminijail.o syscall_filter.o signal_handler.o bpf.o util.o system.o \
	syscall_wrapper.o libconstants.gen.o libsyscalls.gen.o))

ARCH ?= $(shell uname -m)
CXX ?= g++
CFLAGS += -Wall -Werror -O2
CXXFLAGS += -std=c++17
LDFLAGS += -lcap -fPIE -fstack-protector

TEST_CFLAGS += $(CFLAGS)
TEST_CXXFLAGS += $(CXXFLAGS) -isystem googletest/googletest/include
TEST_LDFLAGS += $(LDFLAGS) -pthread

.PHONY: all
all: ${BINARIES} ${POLICIES}

${MINIJAIL_CORE_OBJECT_FILES}: ${MINIJAIL_SOURCE_FILES}
	LDFLAGS= $(MAKE) OUT=${PWD}/minijail -C minijail

minijail/constants.json:
	$(MAKE) OUT=${PWD}/minijail -C minijail constants.json

util.o: util.cpp util.h logging.h macros.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $< -c -o $@

logging.o: logging.cpp logging.h util.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $< -c -o $@

args.o: args.cpp args.h logging.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fexceptions -I cxxopts/include $< -c -o $@

omegajail: main.cpp ${MINIJAIL_CORE_OBJECT_FILES} args.o util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ $(LDFLAGS) -o $@

sigsys-tracer: sigsys_tracer.cpp ${MINIJAIL_CORE_OBJECT_FILES} util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ $(LDFLAGS) -o $@

stdio-mux: stdio_mux.cpp util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ -o $@

java-compile: java_compile.cpp util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Os -fno-exceptions $^ $(LDFLAGS) -static -o $@

policies/%.bpf: policies/%.policy | minijail/constants.json
	./minijail/tools/compile_seccomp_policy.py \
		--use-kill-process --arch-json=minijail/constants.json \
		$^ $@

.PHONY: install
install: ${BINARIES} ${POLICIES}
	install -d $(DESTDIR)/var/lib/omegajail/bin
	install -t $(DESTDIR)/var/lib/omegajail/bin ${BINARIES} omegajail-setup
	install -s -T java-compile $(DESTDIR)/var/lib/omegajail/root-openjdk/compile
	install -d $(DESTDIR)/var/lib/omegajail/policies
	install -t $(DESTDIR)/var/lib/omegajail/policies -m 0644 ${POLICIES}

.PHONY: clean
clean:
	rm -f ${BINARIES} ${POLICIES} *.o
	$(MAKE) OUT=${PWD}/minijail -C minijail clean

.PHONY: test
test: util_test ${BINARIES} ${POLICIES}
	./util_test
	./smoketest/test

util_test.o: util_test.cpp util.h logging.h
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -fno-exceptions $< -c -o $@

util_test: util_test.o util.o logging.o gtest-all.o gtest_main.o
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -fno-exceptions $^ $(TEST_LDFLAGS) -o $@

gtest-all.o : googletest/googletest/src/gtest-all.cc
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -Igoogletest/googletest -fno-exceptions $< -c -o $@

gtest_main.o : googletest/googletest/src/gtest_main.cc
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -Igoogletest/googletest -fno-exceptions $< -c -o $@

.PHONY: mkroot
mkroot: ${BINARIES} ${POLICIES}
	sudo rm -rf $(DESTDIR)/var/lib/omegajail
	sudo ./tools/mkroot --target=$(DESTDIR)/var/lib/omegajail
	sudo $(MAKE) install

.PHONY: package
package: omegajail-bionic-distrib-x86_64.tar.xz omegajail-bionic-rootfs-x86_64.tar.xz

omegajail-bionic-distrib-x86_64.tar.xz:
	tar cJf $@ \
		$(DESTDIR)/var/lib/omegajail/bin \
		$(DESTDIR)/var/lib/omegajail/policies \
		$(DESTDIR)/var/lib/omegajail/root-openjdk/compile

omegajail-bionic-rootfs-x86_64.tar.xz:
	tar cJf $@ \
		--exclude=$(DESTDIR)/var/lib/omegajail/root-openjdk/compile \
		$(DESTDIR)/var/lib/omegajail/root*
