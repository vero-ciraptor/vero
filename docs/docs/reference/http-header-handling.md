# HTTP header handling in `aiohttp`

This project relies on `aiohttp`'s native header containers instead of custom
case-insensitive header helpers.

## Why this is safe

`aiohttp` exposes headers as `multidict.CIMultiDictProxy`, which is
case-insensitive for lookup.

That means all of these are equivalent lookups:

- `headers["Authorization"]`
- `headers["authorization"]`
- `headers.get("AUTHORIZATION")`

## Recommended patterns

- Use constants from `aiohttp.hdrs` when available (`AUTHORIZATION`,
  `CONTENT_TYPE`, `ACCEPT`, etc.).
- Prefer `headers.get(KEY)` when a header is optional.
- Use direct indexing (`headers[KEY]`) only when header presence is mandatory.
- For repeated headers, use `headers.getall(KEY, default)`.

## Current usage in Vero

- Incoming auth header checks use `request.headers.get(hdrs.AUTHORIZATION)`.
- Beacon node response checks use `resp.headers.get(CONTENT_TYPE)` and
  `resp.content_type`.
- Tests normalize mocked request headers through a `CIMultiDictProxy` adapter to
  preserve production-like, case-insensitive behavior.
