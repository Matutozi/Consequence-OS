# Build the binaries with the Go toolchain, then copy them into a minimal
# image with no shell or package manager.
#
# The build stage always runs on the builder's own CPU ($BUILDPLATFORM) and
# cross-compiles for the target, so an arm64 image builds as fast as an
# amd64 one, without emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
WORKDIR /src

# Download modules first, so code changes don't redo this slow step.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS TARGETARCH
ARG VERSION=dev
# CGO_ENABLED=0 makes fully static binaries that run on the empty base image.
RUN for cmd in consequenced mockmcp; do \
      CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
        -ldflags="-s -w -X main.version=$VERSION" -o /out/$cmd ./cmd/$cmd || exit 1; \
    done

# distroless/static has CA certificates (for SMTP over TLS), time zone data
# and a non-root user.
FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.source="https://github.com/Matutozi/Consequence-OS" \
      org.opencontainers.image.description="ConsequenceOS: policy, human approval and signed receipts for AI agent tool calls" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/consequenced /out/mockmcp /usr/local/bin/
COPY consequence.yaml /etc/consequenceos/consequence.yaml
# consequenced looks for consequence.yaml in its working directory, so
# `docker run <image> -check` finds the mounted config without -config.
WORKDIR /etc/consequenceos
USER nonroot
# Inside a container, 127.0.0.1 can't be reached from outside, so listen on
# every interface. -listen or a different CONSEQUENCE_LISTEN overrides it.
ENV CONSEQUENCE_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/consequenced"]
