GOBIN    := $(shell which go)
GO       := GO15VENDOREXPERIMENT=1 $(GOBIN)
BUILDPRE := auditconstant_string.go

test: $(BUILDPRE)
	sudo $(GO) test -v

auditconstant_string.go: audit_constant.go
	$(GO) get golang.org/x/tools/cmd/stringer
	$(GO) generate

clean:
	rm -f $(BUILDPRE)
