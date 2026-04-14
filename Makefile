.PHONY: all build shell test test-san check clean

DOCKER_CMD := docker compose run --rm devcontainer bash -c

all: clean build test check

build:
	@echo "==> Compiling flb-in_dnstap.so in Docker..."
	@$(DOCKER_CMD) "mkdir -p build && cd build && cmake -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DFLB_SOURCE=/tmp/fluent-bit -DPLUGIN_NAME=in_dnstap ../ && make -j$$(nproc)"

shell:
	@echo "==> Opening interactive bash shell in devcontainer..."
	@docker compose run --rm devcontainer bash

test:
	@echo "==> Compiling and running standalone unit tests inside Docker..."
	@$(DOCKER_CMD) "mkdir -p build-test && cd build-test && cmake ../tests && make -j$$(nproc) && ctest --output-on-failure"

test-san:
	@echo "==> Compiling and running unit tests with sanitizers inside Docker..."
	@$(DOCKER_CMD) "mkdir -p build-san && cd build-san && cmake -DCMAKE_C_FLAGS=\"-fsanitize=address,undefined -fno-omit-frame-pointer -g\" -DCMAKE_EXE_LINKER_FLAGS=\"-fsanitize=address,undefined\" ../tests && make -j$$(nproc) && ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 ctest --output-on-failure"

check:
	@$(DOCKER_CMD) "cppcheck --enable=all --error-exitcode=1 --suppress=missingInclude --suppress=*:in_dnstap/dnstap.pb-c.h -i in_dnstap/dnstap.pb-c.c in_dnstap/"

clean:
	@echo "==> Cleaning host build directories..."
	@rm -rf build build-test build-san
