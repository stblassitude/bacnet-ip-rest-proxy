# syntax=docker/dockerfile:1

FROM golang:1.27 AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/bacnet-ip-rest-proxy ./cmd/bacnet-ip-rest-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bacnet-ip-rest-proxy /usr/local/bin/bacnet-ip-rest-proxy
COPY config.example.yaml /etc/bacnet-ip-rest-proxy/config.yaml

EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/bacnet-ip-rest-proxy"]
CMD ["-config", "/etc/bacnet-ip-rest-proxy/config.yaml"]
