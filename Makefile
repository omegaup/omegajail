BINARIES := out/bin/omegajail out/bin/java-compile
POLICIES := $(wildcard policies/*.policy)
POLICY_NOTIFY_BINARIES := $(addprefix out/policies/,$(patsubst %.policy,%.bpf,$(notdir $(POLICIES))))
POLICY_SIGSYS_BINARIES := $(addprefix out/policies/sigsys/,$(patsubst %.policy,%.bpf,$(notdir $(POLICIES))))

MKROOT_SOURCE_FILES := Dockerfile.rootfs tools/mkroot tools/java.base.aotcfg \
                       tools/Main.runtimeconfig.json tools/Release.rsp
OMEGAJAIL_RELEASE ?= $(shell git describe --tags)
DESTDIR ?= /var/lib/omegajail

.PHONY: all
all: $(BINARIES) $(POLICY_NOTIFY_BINARIES) $(POLICY_SIGSYS_BINARIES)

out/bin:
	mkdir -p "$@"

out/policies:
	mkdir -p "$@"

out/policies/sigsys: out/policies
	mkdir -p "$@"

minijail/constants.json:
	$(MAKE) OUT=${PWD}/minijail -C minijail constants.json

out/bin/omegajail: $(shell find src/ -name '*.rs') | out/bin
	cargo build --release --target x86_64-unknown-linux-musl --bin=omegajail
	cp target/release/omegajail $@

out/bin/java-compile: src/java_compile.rs | out/bin
	cargo build --release --target x86_64-unknown-linux-musl --bin=java-compile
	cp target/release/java-compile $@

out/policies/%.bpf: policies/%.policy policies/base/omegajail.policy | minijail/constants.json out/policies
	./minijail/tools/compile_seccomp_policy.py \
		--use-kill-process \
		--default-action=user-notify \
		--arch-json=minijail/constants.json \
		$< $@

out/policies/sigsys/%.bpf: policies/%.policy policies/base/omegajail.policy | minijail/constants.json out/policies/sigsys
	./minijail/tools/compile_seccomp_policy.py \
		--use-kill-process \
		--arch-json=minijail/constants.json \
		$< $@

.PHONY: install
install: $(BINARIES) $(POLICY_NOTIFY_BINARIES) $(POLICY_SIGSYS_BINARIES) tools/omegajail-setup tools/omegajail-cgroups-wrapper
	install -d $(DESTDIR)/bin $(DESTDIR)/policies $(DESTDIR)/policies/sigsys
	install -t $(DESTDIR)/bin $(BINARIES) tools/omegajail-setup tools/omegajail-cgroups-wrapper
	install -t $(DESTDIR)/policies -m 0644 $(POLICY_NOTIFY_BINARIES)
	install -t $(DESTDIR)/policies/sigsys -m 0644 $(POLICY_SIGSYS_BINARIES)

.PHONY: clean
clean:
	rm -rf out/
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

rootfs: .omegajail-builder-rootfs-runtime.stamp .omegajail-builder-rootfs-setup.stamp $(BINARIES) tools/omegajail-setup $(POLICY_NOTIFY_BINARIES) $(POLICY_SIGSYS_BINARIES)
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
