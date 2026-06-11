# Copyright 2026 The cloud-boot Authors.
# SPDX-License-Identifier: BSD-3-Clause
#
# Convenience targets for the genufs/ helper. The canonical interfaces
# are genufs.sh (for shell callers) and genufs.Refresh() (for Go
# callers); this Makefile is a thin alias so contributors used to
# `make image` / `make verify` have a familiar entry point.

GENUFS_OUT      ?= /tmp/genufs/ufs2-fresh.img
GENUFS_LABEL    ?= rootfs
DOCKER_IMG      ?= cloudboot/makefs:freebsd
REPO_ROOT       := $(shell git -C $(CURDIR) rev-parse --show-toplevel 2>/dev/null)

.PHONY: image verify test docker clean help

help:
	@echo "Targets:"
	@echo "  image    — build a fresh UFS2 image at $(GENUFS_OUT)"
	@echo "  verify   — open the image via go-filesystems/ufs and assert structure"
	@echo "  test     — go test ./... (unit tests for the genufs Go wrapper)"
	@echo "  docker   — (re)build the local $(DOCKER_IMG) image used by Option B"
	@echo "  clean    — remove /tmp/genufs (image + staging tree)"

image:
	@GENUFS_OUT=$(GENUFS_OUT) GENUFS_LABEL=$(GENUFS_LABEL) bash $(CURDIR)/genufs.sh

verify:
	@cd $(REPO_ROOT) && go run ./internal/livefreebsdboot/genufs/verify --image $(GENUFS_OUT) --label $(GENUFS_LABEL)

test:
	@cd $(REPO_ROOT) && go test ./internal/livefreebsdboot/genufs/...

docker:
	@docker build -t $(DOCKER_IMG) -f $(CURDIR)/Dockerfile.makefs $(CURDIR)

clean:
	@chmod -R u+rwX /tmp/genufs 2>/dev/null || true
	@rm -rf /tmp/genufs
	@echo "removed /tmp/genufs"
