# Configuration

The proxy is configured through a single YAML file, passed with `-config` (default `config.yaml` in the current directory; the packaged systemd unit passes `/etc/bacnet-ip-rest-proxy/config.yaml`).

A commented example ships as [`config.example.yaml`](https://github.com/stblassitude/bacnet-ip-rest-proxy/blob/main/config.example.yaml) in the repository root, and is installed as the initial `/etc/bacnet-ip-rest-proxy/config.yaml` by the `.deb` package.

## Top-level structure

```yaml
listen:
  address: "0.0.0.0:8443"
  tls:
    enabled: true
    certFile: /etc/bacnet-ip-rest-proxy/cert.pem
    keyFile: /etc/bacnet-ip-rest-proxy/key.pem

bacnet:
  localPort: 0
  timeout: 3s
  retries: 3

authentication:
  tokens:
    - name: ops
      token: "opaque-bearer-token"
  jwtSecret: "shared-secret-for-hmac-sha256"

authorization:
  rules: []

devices:
  default: 192.168.3.2
  integra: integra-controller.example.com
```

## `listen`

The HTTP(S) listener.

| Key | Default | Description |
| --- | --- | --- |
| `listen.address` | `:8443` | `host:port` the server listens on |
| `listen.tls.enabled` | `false` | enable HTTPS |
| `listen.tls.certFile` | — | PEM certificate file (required if `tls.enabled`) |
| `listen.tls.keyFile` | — | PEM private key file (required if `tls.enabled`) |

## `bacnet`

Settings for the BACnet/IP client the proxy uses to talk to devices.

| Key | Default | Description |
| --- | --- | --- |
| `bacnet.localPort` | `0` | local UDP port to bind for outgoing BACnet/IP traffic; `0` picks an ephemeral port |
| `bacnet.timeout` | `3s` | per-attempt reply timeout (Go duration syntax, e.g. `3s`, `500ms`) |
| `bacnet.retries` | `3` | retries per request before giving up |

The proxy only ever initiates **unicast** requests to configured devices — it never broadcasts — so binding a non-standard local port is fine; it does not need to match the BACnet/IP standard port 47808 the way a passive/discoverable device would.

## `devices`

A map of device aliases to hostname/IP (optionally `host:port`; default port 47808):

```yaml
devices:
  default: 192.168.3.2
  integra: integra-controller.example.com
```

A caller can always address a device by a literal hostname/IP directly in the URL, whether or not it appears in this map — the map only exists to let clients use short, stable names instead of raw addresses. The proxy resolves each device's actual BACnet instance number lazily via a unicast Who-Is/I-Am exchange, and caches it for the life of the process.

## `authentication`

Bearer credentials, presented as `Authorization: Bearer <value>`, are checked in this order:

1. **Opaque tokens** (`authentication.tokens`) — an exact-match list. Each entry has a `name` (referenced by authorization rules) and a `token` (the literal secret value):

    ```yaml
    authentication:
      tokens:
        - name: ops
          token: "a-long-random-opaque-string"
    ```

2. **JWT** — if the bearer doesn't match a configured opaque token, it's parsed and verified as a JWT signed with HMAC-SHA256, using the shared secret `authentication.jwtSecret`:

    ```yaml
    authentication:
      jwtSecret: "a long random shared secret"
    ```

    If `jwtSecret` is unset, JWT bearers are never considered valid — only opaque tokens are recognized.

A request that matches neither still reaches the authorization engine, just with no token name or JWT claims to match against — meaning only rules with no such conditions (or IP-only rules) can grant it access.

## `authorization`

An ordered list of rules deciding what a request is allowed to do. This is the security-critical part of the configuration — read it carefully.

### Evaluation algorithm

- Rules are evaluated **in the order given**.
- For each rule, its `conditions` are checked against the request; whether the rule *applies* is controlled by `match` (see below).
- If a rule applies, it overwrites the **provisional result** (`permission` and whether the request is allowed) — regardless of whether its action is `allow`/`deny` or `allow-now`/`deny-now`.
- An `-now` action (`allow-now` or `deny-now`) **stops evaluation immediately**; a plain `allow`/`deny` lets evaluation continue, so a later rule can still override it.
- If no rule applies at all, the **implicit default is deny**.

In other words: the last matching rule wins, unless an earlier rule used `allow-now`/`deny-now` to short-circuit first.

### Rule fields

```yaml
authorization:
  rules:
    - name: admins get full access
      conditions:
        - type: jwt
          field: group
          value: admins
      match: all
      permission: readwrite
      action: allow
```

| Field | Description |
| --- | --- |
| `name` | free-text label, shown in logs/diagnostics |
| `conditions` | list of conditions to test (see below) |
| `match` | how the conditions combine into "this rule applies" (see below) |
| `permission` | `readonly` or `readwrite` — the access level granted if this rule wins. Only meaningful for `allow`/`allow-now` rules |
| `action` | `allow`, `deny`, `allow-now`, or `deny-now` |

### Conditions

Each condition is a `type`/`value` pair (plus `field` for `jwt`). **Wildcards apply to values**: `*` matches anything, and glob patterns like `foo*` or `*.example.com` are supported.

| Type | Matches against | Notes |
| --- | --- | --- |
| `device` | the targeted device (the alias or literal host/IP from the URL) | |
| `ip` | the connecting client's IP | besides wildcards, also accepts CIDR notation (`10.0.0.0/8`) for both IPv4 and IPv6 |
| `jwt` | a claim in the verified JWT payload | requires `field` (the claim name); if the claim is a JSON array (e.g. a `groups` claim), the condition matches if *any* element matches |
| `operation` | the BACnet operation the request maps to | one of `who-is`, `read-property`, `read-property-multiple`, `write-property`, or the synthetic `list-devices` (for `GET /devices`, which makes no BACnet call) |
| `token` | the `name` of a matched entry in `authentication.tokens` | never matches if the bearer wasn't a recognized opaque token (there's no such thing as "no token" matching a wildcard) |

A `jwt` or `token` condition never matches a request that didn't carry the corresponding credential — even against a `*` wildcard.

### Matching modes

`match` controls how the condition list combines into a yes/no for "this rule applies":

| Mode | Rule applies when… |
| --- | --- |
| `all` | every condition matches |
| `any` | at least one condition matches |
| `none` | **no** condition matches |
| `not-all` | at least one condition does **not** match |

!!! danger "Pitfall: `match: none` with a condition that always matches"
    A condition with value `*` always matches — so pairing it with `match: none` produces a rule that can *never* apply, since "at least one condition matched" defeats `none` outright. If you want an issuer guard like:

    ```yaml
    - name: only accept our IdP's tokens
      conditions:
        - type: jwt
          field: iss
          value: id.example.com
      match: none
      action: deny-now
    ```

    (deny immediately unless the issuer matches), don't add an extra `{type: operation, value: "*"}` condition to that same rule — it will silently make the guard inert.

### A worked example

```yaml
authorization:
  rules:
    - name: deny anyone not issued by our IdP
      conditions:
        - type: jwt
          field: iss
          value: id.example.com
      match: none
      action: deny-now

    - name: admins get full access
      conditions:
        - type: jwt
          field: group
          value: admins
      match: all
      permission: readwrite
      action: allow

    - name: everyone else from the office network gets read-only
      conditions:
        - type: ip
          value: 10.10.0.0/16
      match: all
      permission: readonly
      action: allow
```

Reading this top to bottom: any JWT not issued by `id.example.com` is denied outright. Admins (matched by JWT `group` claim) get full read/write access. Anyone else connecting from the `10.10.0.0/16` network gets read-only access. Everyone else falls through to the implicit deny.

## Permission levels and operations

| Permission | Grants |
| --- | --- |
| `readonly` | `who-is`, `read-property`, `read-property-multiple`, `list-devices` |
| `readwrite` | all of the above, plus `write-property` |

Each REST endpoint maps to exactly one of these operations; see the [API Reference](api.md) for the endpoint list.
