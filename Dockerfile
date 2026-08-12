# Build stage: compile the gatekeeper binary.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=$(cat VERSION 2>/dev/null || echo action)" \
    -o /out/gatekeeper ./cmd/gatekeeper

# Runtime stage: the action image bundles the docker CLI (to drive the sandbox
# via the mounted host daemon) and tfsec (optional IaC enrichment).
FROM alpine:3.20
RUN apk add --no-cache docker-cli git ca-certificates \
    && wget -qO /usr/local/bin/tfsec https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 \
    && chmod +x /usr/local/bin/tfsec || true
COPY --from=build /out/gatekeeper /usr/local/bin/gatekeeper
ENTRYPOINT ["/usr/local/bin/gatekeeper"]
CMD ["run"]
