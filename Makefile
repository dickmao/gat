XDG_CONFIG_HOME ?= $(HOME)/.config

.PHONY: install
install: $(XDG_CONFIG_HOME)/gat/source-gat bashrc
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
test:
	go test -race -test.timeout 120s

.PHONY: test-with-coverage
test-with-coverage:
	ginkgo -r -cover -race -skipPackage="testdata"
