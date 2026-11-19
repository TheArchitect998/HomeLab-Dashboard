FROM golang:1.24-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nodesentinel ./cmd/nodesentinel

FROM debian:bookworm-slim

WORKDIR /opt/nodesentinel
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p frontend state \
    && chown 10001:10001 state \
    && chmod 700 state

COPY --from=build /out/nodesentinel /usr/local/bin/nodesentinel
COPY frontend/index.html frontend/index.html

USER 10001:10001
EXPOSE 8888
CMD ["/usr/local/bin/nodesentinel", "dashboard"]
