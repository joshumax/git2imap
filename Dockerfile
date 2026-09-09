# syntax=docker/dockerfile:1
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/git2imap ./cmd/git2imap

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git openssh-client \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --create-home --uid 10001 git2imap \
    && mkdir -p /var/lib/git2imap /var/cache/git2imap \
    && chown -R git2imap:git2imap /var/lib/git2imap /var/cache/git2imap
COPY --from=build /out/git2imap /usr/local/bin/git2imap
COPY config.docker.yaml /etc/git2imap/config.yaml
USER git2imap
EXPOSE 8080 1143 1025 993 465
VOLUME ["/var/lib/git2imap", "/var/cache/git2imap"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail --silent http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["git2imap"]
CMD ["serve", "-config", "/etc/git2imap/config.yaml"]
