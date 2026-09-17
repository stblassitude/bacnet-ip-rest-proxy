# API Reference

The proxy addresses BACnet objects and properties directly as REST resources:

```
GET  /api/v1/devices
GET  /api/v1/devices/{deviceId}
GET  /api/v1/devices/{deviceId}/objects
GET  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}
GET  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}/{property}[?index=N]
PUT  /api/v1/devices/{deviceId}/objects/{objectType}/{instance}/{property}
```

- `deviceId` — a configured alias (see [`devices`](configuration.md#devices)), or a literal hostname/IP.
- `objectType` — a BACnet object type name, e.g. `analog-input`, `binary-output`, `multi-state-value`.
- `instance` — the object's instance number.
- `property` — a BACnet property name, e.g. `present-value`, `object-name`, `description`.

`PUT` takes a JSON body `{"value": ..., "priority": 1-16}`; a `null` value relinquishes that priority (default 16) on a commandable property.

A running instance of the proxy also serves this same specification at `/openapi.yaml`, with an interactive (non-offline) Swagger UI at `/docs`. The reference below is rendered entirely offline from the same spec, bundled with this documentation site.

<swagger-ui src="openapi.yaml"/>
