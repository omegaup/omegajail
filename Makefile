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
OMEGAJAIL_RELEASE ?= $(shell git describe --tags)
DESTDIR ?= /var/lib/omegajail

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

version.o: version.cpp version.h
	$(CXX) "-DOMEGAJAIL_VERSION=\"$(OMEGAJAIL_RELEASE)\"" \
		$(CFLAGS) $(CXXFLAGS) -fno-exceptions $< -c -o $@

util.o: util.cpp util.h logging.h macros.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $< -c -o $@

logging.o: logging.cpp logging.h util.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $< -c -o $@

args.o: args.cpp args.h logging.h version.h
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fexceptions -I cxxopts/include $< -c -o $@

omegajail: main.cpp ${MINIJAIL_CORE_OBJECT_FILES} args.o util.o logging.o version.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ $(LDFLAGS) -o $@

sigsys-tracer: sigsys_tracer.cpp ${MINIJAIL_CORE_OBJECT_FILES} util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ $(LDFLAGS) -o $@

stdio-mux: stdio_mux.cpp util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -fno-exceptions $^ $(LDFLAGS) -o $@

java-compile: java_compile.cpp util.o logging.o
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Os -fno-exceptions $^ $(LDFLAGS) -static -o $@

policies/%.bpf: policies/%.policy | minijail/constants.json
	./minijail/tools/compile_seccomp_policy.py \
		--use-kill-process --arch-json=minijail/constants.json \
		$^ $@

.PHONY: install
install: ${BINARIES} ${POLICIES}
	install -d $(DESTDIR)/bin
	install -t $(DESTDIR)/bin ${BINARIES} omegajail-setup
	install -d $(DESTDIR)/policies
	install -t $(DESTDIR)/policies -m 0644 ${POLICIES}

.PHONY: clean
clean:
	rm -f ${BINARIES} ${POLICIES} *.o
	sudo rm -rf rootfs
	$(MAKE) OUT=${PWD}/minijail -C minijail clean

.PHONY: test
test: util_test
	./util_test

.PHONY: smoketest
smoketest: ${BINARIES} ${POLICIES} rootfs
	./smoketest/test --root=./rootfs

util_test.o: util_test.cpp util.h logging.h
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -fno-exceptions $< -c -o $@

util_test: util_test.o util.o logging.o gtest-all.o gtest_main.o
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -fno-exceptions $^ $(TEST_LDFLAGS) -o $@

gtest-all.o : googletest/googletest/src/gtest-all.cc
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -Igoogletest/googletest -fno-exceptions $< -c -o $@

gtest_main.o : googletest/googletest/src/gtest_main.cc
	$(CXX) $(TEST_CFLAGS) $(TEST_CXXFLAGS) -Igoogletest/googletest -fno-exceptions $< -c -o $@

rootfs: Dockerfile.rootfs tools/mkroot tools/java.base.aotcfg ${BINARIES} ${POLICIES}
	sudo rm -rf rootfs
	$(MAKE) DESTDIR=rootfs install
	docker build \
		-t omegaup/omegajail-builder-rootfs-setup \
		--file Dockerfile.rootfs \
		--target setup \
		.
	docker run \
		--rm \
		--mount "type=bind,source=${PWD}/rootfs,target=/var/lib/omegajail" \
		omegaup/omegajail-builder-rootfs-setup ./tools/mkroot --no-link

omegajail-focal-rootfs-x86_64.tar.xz: Dockerfile.rootfs tools/mkroot tools/java.base.aotcfg
	rm -f omegajail-focal-rootfs-x86_64.tar.xz
	docker build \
		-t omegaup/omegajail-builder-rootfs-package \
		--file Dockerfile.rootfs \
		--target package \
		.
	id=$$(docker create omegaup/omegajail-builder-rootfs-package) && \
	docker cp $${id}:/src/omegajail-focal-rootfs-x86_64.tar.xz omegajail-focal-rootfs-x86_64.tar.xz && \
	docker rm $${id}

omegajail-focal-distrib-x86_64.tar.xz: Dockerfile.distrib Makefile $(wildcard *.h *.cpp omegajail-setup policies/*.frequency policies/*.policy)
	rm -f omegajail-focal-distrib-x86_64.tar.xz
	docker build \
		--build-arg OMEGAJAIL_RELEASE=$(OMEGAJAIL_RELEASE) \
		-t omegaup/omegajail-builder-distrib \
		--file Dockerfile.distrib \
		.
	id=$$(docker create omegaup/omegajail-builder-distrib) && \
	docker cp $${id}:/src/omegajail-focal-distrib-x86_64.tar.xz omegajail-focal-distrib-x86_64.tar.xz && \
	docker rm $${id}
