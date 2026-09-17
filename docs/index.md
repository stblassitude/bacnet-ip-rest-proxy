# Bacnet/IP REST Proxy

**bacnet-ip-rest-proxy** is a REST-to-BACnet/IP translator: clients make HTTP(S) calls to query and update BACnet objects, and the proxy translates them into the corresponding BACnet/IP messages sent to a target BACnet/IP device. It provides HTTPS, bearer-token/JWT authentication, and a rule-based authorization engine to control access to the BACnet/IP devices behind it.

There is no single widely-adopted vendor-neutral standard for exposing BACnet over a REST/JSON API (ASHRAE's BACnet/WS is SOAP/XML-based and rarely implemented; oBIX is XML-first and niche). This proxy instead exposes a small, direct REST mapping onto BACnet's own object/property model, so anyone familiar with BACnet addressing (object type, instance, property) can use it without extra translation.

## What it does

- Addresses BACnet objects and properties directly as REST resources: `GET`/`PUT` a property's value over HTTP instead of speaking BACnet/IP yourself.
- Resolves a device's BACnet instance number automatically via Who-Is/I-Am, so callers only need a hostname or IP.
- Gates every request through a bearer-token or JWT check, then an ordered rule list that decides whether the request is allowed and at what permission level (`readonly` or `readwrite`).
- Serves its own [OpenAPI specification](api.md) and an offline Swagger UI, so the API is self-documenting.

## Where to go next

- [Installation](installation.md) — installing from a release `.deb`, or building from source.
- [Configuration](configuration.md) — the YAML configuration file: listener/TLS, BACnet client settings, authentication, authorization rules, and device aliases.
- [API Reference](api.md) — the full REST API, browsable offline.

## Source

The project lives at [github.com/stblassitude/bacnet-ip-rest-proxy](https://github.com/stblassitude/bacnet-ip-rest-proxy). Issues and pull requests are welcome there.
