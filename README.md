# Bacnet/IP REST Proxy

This tools provides a REST interface to Bacnet/IP translator: clients use HTTP REST calls to query and update Bacnet objects, which get translated into the respective Bacnet/IP messages and sent to a target Bacnet/IP device. It implements HTTPS, authentication and authorization to control access to the Bacnet/IP devices.

## Configuration

The proxy is configured through YAML file. Unknown keys are an error, and every configuration error is reported with its line number.

### Listening and HTTPS

```yaml
listen:
  address: "0.0.0.0:8443"   # host:port the HTTP(S) server listens on
  tls:
    enabled: true
    certFile: /etc/bacnet-ip-rest-proxy/cert.pem
    keyFile: /etc/bacnet-ip-rest-proxy/key.pem
  trustedProxies:
    - 127.0.0.1/32
```

`listen.address` defaults to `:8443`. TLS is optional; when `tls.enabled` is `true`, both `certFile` and `keyFile` are required.

`listen.trustedProxies` is a list of IPs/CIDRs. When the proxy runs behind a reverse proxy (nginx, Caddy, a load balancer, ...), the connecting TCP peer is always that reverse proxy, not the real client — so the `ip` authorization condition needs the real client's address from the `X-Forwarded-For` or `X-Real-IP` header instead. Those headers are only honored when the immediate TCP peer's address is in `trustedProxies`; otherwise they're ignored, so a client can't spoof its way past an `ip` condition by just setting the header itself. Only a single hop is supported: the leftmost `X-Forwarded-For` entry is taken as the real client. Leave `trustedProxies` empty (the default) if the proxy is reachable directly.

### `bacnet`

Settings for the BACnet/IP client the proxy uses to talk to devices:

```yaml
bacnet:
  localPort: 0     # local UDP port to bind; 0 (default) picks an ephemeral port
  timeout: 3s       # default 3s; per-attempt reply timeout
  retries: 3        # default 3; retries per request before giving up
  cacheRefresh: 60s # default 60s; how often each device's variable list and names are re-read
```

### `authentication.tokens`

A list of API tokens that can be used for authentication. Each entry is a map of a name for the token, and the literal token that can be supplied in an `Authentication: Bearer` header. The value is an opaque string without any further meaning. You will need to add authorization rules that match the names in these tokens.

### `authorization`

A list of rules, with each coontaining these fields. See below for details

### Example: allowing group "admins" full access

```yaml
authorization:
  rules:
    - name: ensure token has been issued by our IDP
      conditions:
        - type: jwt
          field: iss
          value: id.example.com
      match: none
      action: deny-now
    - name: admins are allowed full access
      conditions:
        - type: jwt
          field: group
          value: admins
      match: all
      permission: readwrite
      action: allow
```

### `devices`

A map of Bacnet/IP device aliases. A caller can always specify any Bacnet/IP target device IP or hostname, but these aliases can be used to decouple the actual hostnames/IPs from what the caller uses. Example:

```yaml
devices:
  default: 192.168.3.2
  integra: integra-controller.example.com
```

## Authentication

The proxy can use `Authentication: Bearer` JWT tokens. The token must validate to be considered valid. JWT signatures are verified with an HMAC-SHA256 shared secret configured as `authentication.jwtSecret`:

```yaml
authentication:
  jwtSecret: "a long random shared secret"
```

If `authentication.jwtSecret` is not set, JWT bearers are never considered valid (only opaque tokens from `authentication.tokens` are recognized).

The proxy also allows custom API tokens, see `authentication.tokens`.

A request's bearer value is checked against `authentication.tokens` first (exact match); if it doesn't match a configured token, it is parsed and verified as a JWT instead.

## Authorization: `authorization`

The proxy optionally takes a list of rules to determine which request is allowed which operation. Rules are evaluated in the order they are given in the configuration. Evaluation continues until all rules have been checked, or a `-now` action is taken.

Each request is evaluated against all rules. If the conditions in the rule are not matched, the rule is ignored. If the rule matches, a provisional result (permission and action) is updated. There is an implicit first rule, using no conditions, and an action of `deny`.

After all rules have been evaluated, the provisional result becomes the actual result, and access is granted with the computed permission, or denied.

### `conditions`

A list of conditions that should be matched. Each entry is a type/value pair. Wildcards apply to values.

* type `device`: The targeted device
* type `ip`: the IP address of the connecting client. In addition to the wildcard matching on a string basis, also accepts IP/mask syntax for both IPv4 and IPv6.
* type `jwt`: the additional key `field` picks the field in the JWT payload
* type `operation`: any of the Bacnet/IP operations: `who-is`, `read-property`, `read-property-multiple`, `write-property`, or the synthetic `list-devices` (for `GET /devices`, which makes no BACnet call)
* type `token`: the name of a token defined in the `authentication.tokens` section.
* type `variable`: the name of a BACnet object (its `object-name`, as reported by the device). Rules are evaluated separately for each variable; a rule without a `variable` condition applies to all variables alike.

### Variables

The proxy enumerates each device's objects ("variables") on first use and re-reads the list and every object's name every `bacnet.cacheRefresh` (default 60s). Authorization is applied per variable, using those cached names:

* writes to a variable are denied unless the caller has `readwrite` access to it;
* responses leave out variables the caller can't read: the object list, a device's `object-list` property, and single-object reads (`403`);
* every returned variable carries an `access` field, `readonly` or `readwrite`, with the caller's effective right on it.

When any rule has a `variable` condition, requests for objects that aren't in the cached list (e.g. created since the last refresh) are denied until the next refresh, and a renamed object keeps its old name for authorization for up to one refresh interval.

### `permission`

The access level a matching rule grants: `readonly` or `readwrite`. Read operations (`who-is`, `read-property`, `read-property-multiple`, `list-devices`) require at least `readonly`; `write-property` requires `readwrite`. `permission` is only meaningful on `allow`/`allow-now` rules.

### `matching`

Condition matching is controlled by the `match` field:
* `none`: **none** of the conditions **must match** for the rule to apply
* `not-all`: **at least one** of the conditions **must not match** for the rule to apply
* `any`: **at least one** of the conditions **must match** for the rule to apply
* `all`: **all** of the conditions **must match** for the rule to apply

### `action`

Determines the outcome of the rule:
  * `allow-now`: the request is allowed, and evaluation stops
  * `deny-now`: the request is denied, and evaluation stops
  * `allow`: the request is allowed if no other rule denies it
  * `deny`: the request is denied if no later rule allows it

Note: because `allow`/`deny` (like `allow-now`/`deny-now`) overwrite the provisional result on every match, a later matching rule always overrides an earlier one; "if no other rule denies/allows it" means "unless a later rule matches and says otherwise".

## REST API

Devices, objects and properties are addressed directly using BACnet's own naming:

```
GET  /api/v1/devices
GET  /api/v1/devices/{deviceId}
GET  /api/v1/devices/{deviceId}/objects
GET  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}
GET  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}/{property}[?index=N]
PUT  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}/{property}
```

`deviceId` is resolved against the `devices` alias map first, falling back to treating it as a literal hostname/IP (optionally `host:port`, default port 47808). `objectType` is one of `analog-input`, `analog-output`, `analog-value`, `binary-input`, `binary-output`, `binary-value`, `device`, `multi-state-input`, `multi-state-output`, `multi-state-value`. `property` is a BACnet property name such as `present-value`, `object-name`, `description`, `units`, `status-flags`.

`PUT` takes a JSON body `{"value": ..., "priority": 1-16}`; a `null` value relinquishes that priority (default 16) on a commandable property.

The full request/response shapes are in the OpenAPI spec, served by the running proxy at `/openapi.yaml`, with an interactive Swagger UI at `/docs`.

## Development

The BACnet/IP wire protocol (`internal/bacnet`), the mock BACnet/IP device used for testing (`internal/bacnetmock`), the authorization engine (`internal/authz`), authentication (`internal/auth`), and the HTTP API (`internal/api`) each have their own tests. Run everything with:

```sh
go test ./...
```

No physical BACnet hardware is required: `internal/bacnetmock` implements a real (if minimal) BACnet/IP device over UDP for tests to run against.
