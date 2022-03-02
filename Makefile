BINARIES := omegajail java-compile
POLICIES := policies/gcc.bpf policies/cpp.bpf policies/ghc.bpf policies/hs.bpf \
            policies/javac.bpf policies/java.bpf policies/fpc.bpf policies/pas.bpf \
            policies/pyc.bpf policies/py.bpf policies/ruby.bpf policies/lua.bpf \
            policies/csc.bpf policies/cs.bpf policies/js.bpf policies/karel.bpf \
            policies/cpp-asan.bpf policies/clang.bpf \
            policies/go.bpf policies/go-build.bpf \
            policies/rustc.bpf policies/rs.bpf

MINIJAIL_SOURCE_FILES := $(addprefix minijail/,\
	$(cd minijail && git ls-tree --name-only HEAD -- *.c *.c))
MKROOT_SOURCE_FILES := Dockerfile.rootfs tools/mkroot tools/java.base.aotcfg \
                       tools/Main.runtimeconfig.json tools/Release.rsp
OMEGAJAIL_RELEASE ?= $(shell git describe --tags)
DESTDIR ?= /var/lib/omegajail

.PHONY: all
all: ${BINARIES} ${POLICIES}

minijail/constants.json:
	$(MAKE) OUT=${PWD}/minijail -C minijail constants.json

omegajail: $(shell find src/ -name '*.rs')
	cargo build --release --bin=$@
	cp target/release/$@ $@

java-compile: src/java_compile.rs
	cargo build --release --bin=$@
	cp target/release/$@ $@

policies/%.bpf: policies/%.policy policies/omegajail.policy | minijail/constants.json
	./minijail/tools/compile_seccomp_policy.py \
		--use-kill-process \
		--default-action=user-notify \
		--arch-json=minijail/constants.json \
		$< $@

.PHONY: install
install: ${BINARIES} tools/omegajail-setup ${POLICIES}
	install -d $(DESTDIR)/bin $(DESTDIR)/policies
	install -t $(DESTDIR)/bin ${BINARIES} tools/omegajail-setup tools/omegajail-cgroups-wrapper
	install -t $(DESTDIR)/policies -m 0644 ${POLICIES}

.PHONY: clean
clean:
	rm -f ${BINARIES} ${POLICIES} *.o
	sudo rm -rf rootfs
	$(MAKE) OUT=${PWD}/minijail -C minijail clean

.PHONY: test
test:
	cargo test

.PHONY: smoketest
smoketest: rootfs
	./smoketest/test --root=./rootfs

.omegajail-builder-rootfs-runtime.stamp: .omegajail-builder-rootfs-setup.stamp .omegajail-builder-distrib.stamp
	docker build \
		-t omegaup/omegajail-builder-rootfs-runtime \
		--target=runtime \
		--file=Dockerfile.rootfs \
		.
	touch $@

.omegajail-builder-rootfs-runtime-debug.stamp: .omegajail-builder-rootfs-runtime.stamp
	docker build \
		-t omegaup/omegajail-builder-rootfs-runtime-debug \
		--target=runtime-debug \
		--file=Dockerfile.rootfs \
		.
	touch $@

.PHONY: smoketest-docker
smoketest-docker: .omegajail-builder-rootfs-runtime-debug.stamp
	docker run \
		--rm \
		--mount "type=bind,source=$(PWD)/smoketest,target=/src" \
		--tmpfs "/home:mode=1777,uid=$(shell id -u),gid=$(shell id -g)" \
		--user "$(shell id -u):$(shell id -g)" \
		omegaup/omegajail-builder-rootfs-runtime-debug \
		/usr/bin/python3 /src/test

.omegajail-builder-rootfs-setup.stamp: ${MKROOT_SOURCE_FILES}
	docker build \
		-t omegaup/omegajail-builder-rootfs-setup \
		--file Dockerfile.rootfs \
		--target rootfs-setup \
		.
	touch $@

rootfs: .omegajail-builder-rootfs-runtime.stamp .omegajail-builder-rootfs-setup.stamp ${BINARIES} tools/omegajail-setup ${POLICIES}
	sudo rm -rf $@ ".$@.tmp"
	mkdir ".$@.tmp"
	$(MAKE) DESTDIR=".$@.tmp" install || (sudo rm -rf ".$@.tmp" ; exit 1)
	docker run \
		--rm \
		--mount "type=bind,source=${PWD}/.$@.tmp,target=/var/lib/omegajail" \
		omegaup/omegajail-builder-rootfs-setup /src/mkroot --no-link && \
	mv ".$@.tmp" "$@" || (sudo rm -rf ".$@.tmp" ; exit 1)

.omegajail-builder-rootfs-build.stamp: ${MKROOT_SOURCE_FILES}
	docker build \
		-t omegaup/omegajail-builder-rootfs-build \
		--file Dockerfile.rootfs \
		--target rootfs-build \
		.
	touch $@

omegajail-focal-rootfs-x86_64.tar.xz: .omegajail-builder-rootfs-build.stamp
	rm -f $@
	touch ".$@.tmp"
	docker run \
		--rm \
		--mount "type=bind,source=${PWD}/.$@.tmp,target=/src/$@" \
		--env "XZ_DEFAULTS=-T 0" \
		omegaup/omegajail-builder-rootfs-build \
		/bin/tar cJf "/src/$@" \
		--exclude /var/lib/omegajail/bin \
		--exclude /var/lib/omegajail/policies \
		/var/lib/omegajail/ && \
	mv ".$@.tmp" "$@" || rm ".$@.tmp"

.omegajail-builder-distrib.stamp: Dockerfile.distrib $(wildcard src/*.rs src/jail/*.rs tools/omegajail-setup policies/*.frequency policies/*.policy)
	docker build \
		--build-arg OMEGAJAIL_RELEASE=$(OMEGAJAIL_RELEASE) \
		-t omegaup/omegajail-builder-distrib \
		--file Dockerfile.distrib \
		.
	touch $@

omegajail-focal-distrib-x86_64.tar.xz: .omegajail-builder-distrib.stamp
	rm -f $@
	touch ".$@.tmp"
	docker run \
		--rm \
		--mount "type=bind,source=${PWD}/.$@.tmp,target=/src/$@" \
		--env "XZ_DEFAULTS=-T 0" \
		omegaup/omegajail-builder-distrib \
		/bin/tar cJf "/src/$@" \
		/var/lib/omegajail/bin \
		/var/lib/omegajail/policies && \
	mv ".$@.tmp" "$@" || rm ".$@.tmp"
