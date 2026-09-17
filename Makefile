.PHONY: test test-live-jwks fmt vet verify

test:
	go test ./...

test-live-jwks:
	KUBE_RELEASE_LIVE_GITHUB_JWKS=1 go test -run TestLiveGitHubJWKSRefresh -v ./internal/githubjwks

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

vet:
	go vet ./...

verify: test vet
