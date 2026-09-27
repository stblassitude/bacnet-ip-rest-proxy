# Installation

## From a release `.deb` (Debian/Ubuntu)

Each [GitHub release](https://github.com/stblassitude/bacnet-ip-rest-proxy/releases) publishes a Debian package and a standalone Linux/amd64 binary.

```sh
curl -LO https://github.com/stblassitude/bacnet-ip-rest-proxy/releases/download/v1.0.0/bacnet-ip-rest-proxy_1.0.0_amd64.deb
sudo dpkg -i bacnet-ip-rest-proxy_1.0.0_amd64.deb
```

The package installs:

| Path | Purpose |
| --- | --- |
| `/usr/sbin/bacnet-ip-rest-proxy` | the binary |
| `/etc/bacnet-ip-rest-proxy/config.yaml` | configuration file (see [Configuration](configuration.md)) |
| `/lib/systemd/system/bacnet-ip-rest-proxy.service` | systemd unit |

The config file is marked `noreplace`, so re-installing or upgrading the package never overwrites your edits.

!!! warning
    The installed config ships with an empty rule list, which — per the authorization engine's implicit default — **denies every request**. Edit `/etc/bacnet-ip-rest-proxy/config.yaml` before enabling the service; see [Configuration](configuration.md).

Once configured, enable and start the service:

```sh
sudo systemctl enable --now bacnet-ip-rest-proxy
```

The unit checks the configuration (`bacnet-ip-rest-proxy -configcheck`) before starting the proxy, so a broken config shows up as a failed start with the errors in the journal. Run the same check by hand after editing the config:

```sh
sudo bacnet-ip-rest-proxy -configcheck -config /etc/bacnet-ip-rest-proxy/config.yaml
```

Check its status and logs with:

```sh
systemctl status bacnet-ip-rest-proxy
journalctl -u bacnet-ip-rest-proxy -f
```

## From a container image

Each release also publishes a multi-stage-built, distroless container image to the GitHub Container Registry:

```sh
docker run -d --name bacnet-ip-rest-proxy \
  -p 8443:8443 \
  -v /path/to/config.yaml:/etc/bacnet-ip-rest-proxy/config.yaml:ro \
  ghcr.io/stblassitude/bacnet-ip-rest-proxy:latest
```

The image runs as a non-root user and ships a copy of `config.example.yaml` at `/etc/bacnet-ip-rest-proxy/config.yaml` by default — mount your own file over it as shown above, or build your own image `FROM` it with a `COPY`. Pin a specific version instead of `latest` for anything other than quick testing, e.g. `ghcr.io/stblassitude/bacnet-ip-rest-proxy:1.0.0`.

## From the standalone binary

Download `bacnet-ip-rest-proxy_<version>_linux_amd64` from the release, make it executable, and run it directly with `-config`:

```sh
chmod +x bacnet-ip-rest-proxy_1.0.0_linux_amd64
./bacnet-ip-rest-proxy_1.0.0_linux_amd64 -config /path/to/config.yaml
```

## From source

Requires Go 1.22 or newer.

```sh
git clone https://github.com/stblassitude/bacnet-ip-rest-proxy.git
cd bacnet-ip-rest-proxy
go build -o bacnet-ip-rest-proxy ./cmd/bacnet-ip-rest-proxy
./bacnet-ip-rest-proxy -config config.example.yaml
```

Run the test suite (no physical BACnet hardware needed — a mock BACnet/IP device is used for tests):

```sh
go test ./...
```

## Building the `.deb` locally

The release workflow uses [`nfpm`](https://nfpm.goreleaser.com) to build the package from `packaging/nfpm.yaml`. To build it yourself:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/bacnet-ip-rest-proxy ./cmd/bacnet-ip-rest-proxy
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
VERSION=0.0.0-local ARCH=amd64 nfpm pkg --packager deb --config packaging/nfpm.yaml \
  --target dist/bacnet-ip-rest-proxy_0.0.0-local_amd64.deb
```

## Building the container image locally

```sh
docker build --build-arg VERSION=0.0.0-local -t bacnet-ip-rest-proxy:local .
docker run -d -p 8443:8443 bacnet-ip-rest-proxy:local
```
