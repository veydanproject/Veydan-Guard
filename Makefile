# VGuard. From the repository root the same targets are `make vguard-<target>`.

.PHONY: build test check run release build-deploy third-party clean

SHELL := /bin/bash
ENV := source scripts/env.sh &&

# Debug build.
build:
	@$(ENV) cargo build

test:
	@$(ENV) cargo test

check:
	@$(ENV) cargo clippy --all-targets -- -D warnings

# Runs the guard here, in front of a strfry on 127.0.0.1:7777, with
# vguard.toml next to this file (written from the example on the first run).
run:
	@[ -f vguard.toml ] || cp deploy/vguard.example.toml vguard.toml
	@$(ENV) cargo run -q -p vguard -- serve --config vguard.toml

# Static binary in dist/.
release:
	@bash scripts/build-release.sh

# The static binary copied into the bin folder of a server kit, which installs
# it from there:  make build-deploy DEPLOY_BIN=<folder>
build-deploy: release
	@if [ -z "$(DEPLOY_BIN)" ]; then echo ">> make build-deploy DEPLOY_BIN=<folder>"; exit 1; fi
	@mkdir -p $(DEPLOY_BIN)
	@cp dist/vguard dist/vguard.sha256 dist/vguard.RELEASE $(DEPLOY_BIN)/
	@echo ">> $(DEPLOY_BIN)/vguard  $$(cat dist/vguard.RELEASE)"

# THIRD-PARTY-LICENSES.md from Cargo.lock: run it after the lock changes.
third-party:
	@$(ENV) node scripts/third-party.mjs

clean:
	@rm -rf target dist
