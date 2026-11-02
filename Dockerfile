# Build both binaries with the Go toolchain, then copy them into a minimal
# image with no shell or package manager.
FROM golang:1.27.3-alpine AS build
WORKDIR /src

# Download modules first, so code changes don't redo this slow step.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 makes fully static binaries that run on the empty base image.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/consequenced ./cmd/consequenced && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mockmcp ./cmd/mockmcp

# distroless/static has CA certificates (for SMTP over TLS) and a non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/consequenced /out/mockmcp /usr/local/bin/
COPY consequence.yaml /etc/consequenceos/consequence.yaml
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/consequenced"]
CMD ["-config", "/etc/consequenceos/consequence.yaml"]
