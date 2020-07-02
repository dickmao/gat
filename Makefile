export VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo 0.0.2)
XDG_CONFIG_HOME ?= $(HOME)/.config
XDG_DATA_HOME ?= $(HOME)/.local/share
export PKG_CONFIG_PATH := $(XDG_DATA_HOME)/../lib/pkgconfig:$(PKG_CONFIG_PATH)

define VERSIONGO
package version

const Version string = "$(VERSION)"
endef

export VERSIONGO
.PHONY: version/version.go
version/version.go:
	@mkdir -p version
	echo "$$VERSIONGO" > $@

.PHONY: compile
compile: version/version.go
	go build

.PHONY: install
install: version/version.go $(XDG_CONFIG_HOME)/gat/source-gat bashrc
	go install -v

$(XDG_CONFIG_HOME)/gat/source-gat: source-gat
	mkdir -p $(@D)
	cp -p source-gat $@

.PHONY: bashrc
bashrc:
	@if [ ! -f "$(HOME)/.bashrc" ] && [ ! -f "$(HOME)/.zshrc" ] \
	; then echo gat only supports bash, zsh \
	;      exit 1 \
	; fi
	@for bashrc in "$(HOME)/.bashrc" "$(HOME)/.zshrc" \
	; do if [ -e $$bashrc ] \
	;    then tmpfile=$$(mktemp /tmp/gat.bashrc.XXXXXX) \
	;         if egrep -q "^.*>.*gat config" "$$bashrc" \
	;         then sed -e '/^.*>.*gat config/,/gat config.*<.*$$/{/gat config.*<.*$$/!d;r bashrc-gat' -e 'd}' "$$bashrc" > "$$tmpfile" \
	;         else ( cat "$$bashrc"; echo ; cat bashrc-gat ) >>$$tmpfile \
	;         fi \
	;         if expr $$(diff "$$bashrc" "$$tmpfile" | wc -l) \> 0 >/dev/null\
	;         then if expr $$(diff "$$bashrc" "$$tmpfile" | wc -l) \> 12 >/dev/null \
	;              then echo too many lines different \
	;                   exit 1 \
	;              else cp "$$tmpfile" "$$bashrc" \
	;              fi \
	;         fi \
	;         rm "$$tmpfile" \
	;    fi \
	; done

.PHONY: clean
clean:
	go clean -i

.PHONY: install-tools
install-tools:
	go get -u -v golang.org/x/lint/...
	go get -u -v github.com/kisielk/errcheck/...
	go get -u -v github.com/onsi/ginkgo/ginkgo/...
	go get -u -v github.com/modocache/gover/...
	go get -u -v github.com/mattn/goveralls/...

.PHONY: lint
lint:
	./scripts/lint.sh

.PHONY: test
test: compile
	go test -race -test.timeout 120s
	rm -f ./gat

.PHONY: test-with-coverage
test-with-coverage:
	ginkgo -r -cover -race -skipPackage="testdata"

.PHONY: docs/%
docs/%:
	$(MAKE) -C docs $(@F)
