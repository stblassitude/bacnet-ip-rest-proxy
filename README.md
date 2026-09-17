# Bacnet/IP REST Proxy

This tools provides a REST interface to Bacnet/IP translator: clients use HTTP REST calls to query and update Bacnet objects, which get translated into the respective Bacnet/IP messages and sent to a target Bacnet/IP device. It implements HTTPS, authentication and authorization to control access to the Bacnet/IP devices.

## Configuration

The proxy is configured through YAML file.

### Listening and HTTPS

```yaml
listen:
  address: "0.0.0.0:8443"   # host:port the HTTP(S) server listens on
  tls:
    enabled: true
    certFile: /etc/bacnet-ip-rest-proxy/cert.pem
    keyFile: /etc/bacnet-ip-rest-proxy/key.pem
```

`listen.address` defaults to `:8443`. TLS is optional; when `tls.enabled` is `true`, both `certFile` and `keyFile` are required.

### `bacnet`

Settings for the BACnet/IP client the proxy uses to talk to devices:

```yaml
bacnet:
  localPort: 0     # local UDP port to bind; 0 (default) picks an ephemeral port
  timeout: 3s       # default 3s; per-attempt reply timeout
  retries: 3        # default 3; retries per request before giving up
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
        - operation: *
      match: none
      permission: none
      action: deny-now
    - name: admins are allowed full access
      conditions:
        - type: jwt
          field: group
          value: admins
        - operation: *
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
