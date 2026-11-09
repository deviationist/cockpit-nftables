# cockpit-nftables — trimmed from cockpit-upside's starter-kit Makefile (PoC).
PACKAGE_NAME := $(shell awk '/"name":/ {gsub(/[",]/, "", $$2); print $$2}' package.json)
PREFIX ?= /usr/local
NODE_MODULES_TEST=node_modules/.package-lock.json
DIST_TEST=runtime-npm-modules.txt
COCKPIT_REPO_STAMP=pkg/lib/cockpit-po-plugin.js

all: $(DIST_TEST)

# Cockpit's shared libs (pkg/lib), pinned to the same commit as cockpit-upside
# so PatternFly versions line up with Cockpit 362.
COCKPIT_REPO_FILES = pkg/lib
COCKPIT_REPO_URL = https://github.com/cockpit-project/cockpit.git
COCKPIT_REPO_COMMIT = ca0d360e3a858a7eb189edde15cf7b976018404b # 362
COCKPIT_REPO_TREE = '$(strip $(COCKPIT_REPO_COMMIT))^{tree}'
$(COCKPIT_REPO_STAMP): Makefile
	@git rev-list --quiet --objects $(COCKPIT_REPO_TREE) -- 2>/dev/null || \
	    git fetch --no-tags --no-write-fetch-head --depth=1 $(COCKPIT_REPO_URL) $(COCKPIT_REPO_COMMIT)
	git archive $(COCKPIT_REPO_TREE) -- $(COCKPIT_REPO_FILES) | tar x

$(NODE_MODULES_TEST): package.json
	npm ci

$(DIST_TEST): $(NODE_MODULES_TEST) $(COCKPIT_REPO_STAMP) $(shell find src/ -type f) package.json build.js
	NODE_ENV=$(NODE_ENV) ./build.js

watch: $(NODE_MODULES_TEST) $(COCKPIT_REPO_STAMP)
	NODE_ENV=$(NODE_ENV) ./build.js --watch

test:
	node --test src/lib/*.test.ts

check: test
	npx tsc --noEmit -p .
	npx eslint src/

clean:
	rm -rf dist/ metafile.json runtime-npm-modules.txt

install: $(DIST_TEST)
	mkdir -p $(DESTDIR)$(PREFIX)/share/cockpit/$(PACKAGE_NAME)
	cp -r dist/* $(DESTDIR)$(PREFIX)/share/cockpit/$(PACKAGE_NAME)

# Per-user install for testing: only the current user's Cockpit sees it.
devel-install: $(DIST_TEST)
	mkdir -p ~/.local/share/cockpit
	ln -sfn `pwd`/dist ~/.local/share/cockpit/$(PACKAGE_NAME)

devel-uninstall:
	rm -f ~/.local/share/cockpit/$(PACKAGE_NAME)

.PHONY: all watch test check clean install devel-install devel-uninstall
