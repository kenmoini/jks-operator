# Build the manager binary
# FROM golang:1.24 AS builder
# FROM registry.access.redhat.com/ubi10/go-toolset:1.25-1777537854 AS builder
FROM registry.access.redhat.com/ubi10/ubi:latest AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64

ENV NAME=golang \
    GO_MAJOR_VERSION=1 \
    GO_MINOR_VERSION=26 \
    GO_PATCH_VERSION=2 \
    CONTAINER_NAME="rhel10/go-toolset"
ENV VERSION=$GO_MAJOR_VERSION.$GO_MINOR_VERSION.$GO_PATCH_VERSION

RUN dnf install -y wget tar gzip && \
    dnf clean all && \
    wget -q https://dl.google.com/go/go${VERSION}.linux-${TARGETARCH}.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}" \
    GOPATH="/opt/app-root/go" \
    GOCACHE="/opt/app-root/go/cache" \
    GOMODCACHE="/opt/app-root/go/pkg/mod"

RUN mkdir -p /opt/app-root/src \
    && mkdir -p /opt/app-root/go/cache \
    && mkdir -p /opt/app-root/go/pkg/mod \
    && chown -R 1001:0 /opt/app-root

USER 1001

WORKDIR /opt/app-root/src
# Copy the Go Modules manifests
COPY --chown=1001:0 go.mod go.mod
COPY --chown=1001:0 go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY --chown=1001:0 cmd/main.go cmd/main.go
COPY --chown=1001:0 api/ api/
COPY --chown=1001:0 internal/ internal/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -o manager cmd/main.go

# ==========================================================================================================
FROM registry.access.redhat.com/ubi10/ubi-minimal:latest
RUN microdnf update -y && microdnf install -y ca-certificates && microdnf clean all
WORKDIR /
COPY --from=builder /opt/app-root/src/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
