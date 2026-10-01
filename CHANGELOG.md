# Changelog

## 0.2.0

- Add caller-resolved addresses and caller-owned TLS policy for both mailbox
  streams and reconnects, retaining the original TLS and HTTP authority.
- Add bounded pure pairing validation and semantic pairing commitments.
- Bound aggregate receive retention, complete-control bytes and fragment work;
  saturated sessions terminate without admission waits or reconnects.
- Preserve receive reservations through `Bytes` payloads, clones and slices;
  gather one bounded Noise record instead of copying whole controls.
- Own socket/HTTP2 tasks and wake blocking Noise I/O on cancellation; isolate
  entropy stretching in one bounded process-owned worker.
- Remove secret material and untrusted frame bodies from transport traces.
- Redact public credential Debug output and preserve following stream bytes
  after authenticated empty Noise records.
- Clarify that callers configure mailbox tuning on the transport explicitly.

Public API changes: `ClientConnParams` includes `resolved_address` and
`tls_config`; initialize these optional fields explicitly. `ControlMsg::payload`
is now `Bytes`; convert an owned `Vec<u8>` with `.into()` when constructing it.
Bundled LND protobufs remain at `v0.21.3-beta`; comment formatting is adjusted
for Rust documentation without changing the protocol definitions.
