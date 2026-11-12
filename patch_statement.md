# Codebase Change Statement: quic-go

**Current Codebase:** `zhfreal/quic-go` (`main-patched`, Tag: `v0.61.1-patch2` / `v0.61.1+patch2`)  
**Original Upstream Baseline:** `quic-go/quic-go` (`v0.61.0`, Commit `579ee19d261db7a6ec46a5ef4ad4fa8d9e262c82`)  
**Repository Location:** `./quic-go-mine`  
**Status:** Production-Ready, Race-Verified (`go test -race ./...` passing 100%)

---

## 1. Executive Summary

This document specifies the complete architectural, functional, and security delta between the current codebase (`zhfreal/quic-go @ main-patched`) and the original upstream baseline (`quic-go/quic-go @ v0.61.0`, commit `579ee19d261db7a6ec46a5ef4ad4fa8d9e262c82`).

The modifications against original upstream are organized into two principal categories:
1. **Type 1: New Features**: Full Google Chrome QUIC fingerprint parroting (`ChromeParrot`), RFC 9368 version negotiation and GREASE injection, post-quantum hybrid key exchange (`X25519MLKEM768`), chaos packet packing with randomized padding, pluggable congestion controller interfaces, transport GSO disablement toggles, and unified integration with `github.com/metacubex/utls`.
2. **Type 2: Bug Fixes & Concurrency Remediations**: Elimination of fatal process panics on `QUICErrorEvent` inside the uTLS adapter, defensive nil-pointer safety in connection teardown, restoration of `CurveID` and `ECHAccepted` metadata in connection states, Initial packet number length and coalescing fixes, strict unsupported TLS configuration validation, and transport parameter varint roundtrip integrity.

---

## 2. New Features (Type 1)

### 2.1 Google Chrome QUIC Fingerprint Parroting (`chrome_parrot.go`, `config.go`, `interface.go`)
* **`Config.ChromeParrot` Integration**:
  - Introduced boolean setting `ChromeParrot` on `quic.Config`.
  - Enforces Chrome-identical transport parameters and packet framing when enabled on client connections.
  - Automatically pins standard Chrome tunables: `chromeMaxIdleTimeout` (30s), `chromeInitialMaxStreamData` (6 MiB), `chromeInitialMaxData` (15 MiB), `chromeMaxIncomingStreams` (100), `chromeInitialPacketSize` (1250 bytes), `chromeMaxUDPPayloadSize` (1472 bytes), and `chromeMaxDatagramFrameSize` (65536 bytes).
* **Zero-Length Connection ID Generation (`ZeroLengthConnectionIDGenerator`)**:
  - Implemented `ZeroLengthConnectionIDGenerator` to emit 0-length source connection IDs on the wire, mirroring Google Chrome client behavior.

### 2.2 RFC 9368 QUIC Version Information & GREASE Parameter Generation (`internal/wire/transport_parameters_chrome.go`, `internal/wire/grease_quic_version.go`)
* **Per-Connection Shuffled Transport Parameters**:
  - Shuffled transport parameter emission order on every handshake (`shuffleParams`), avoiding static fingerprint signatures.
* **Version Information & Google Connection Options**:
  - Injected `version_information` parameter (RFC 9368) carrying QUIC v1 and uniformly randomized GREASE version IDs (`0x?a?a?a?a`).
  - Added `google_connection_options` carrying the `ORIG` option tag sent by modern Chrome clients.
* **Large-ID GREASE Parameter Injection**:
  - Added high-range GREASE transport parameter (`31 * N + 27`) with variable-length random payload values.

### 2.3 Chrome ClientHello Parroting with Post-Quantum Hybrid Key Exchange (`internal/handshake/chrome_client_hello.go`)
* **QUIC-Specific ClientHello Spec**:
  - Created dedicated QUIC ClientHello specification rather than reusing TCP/h2 fingerprints.
  - Negotiates `h3` via ALPN with randomized extension ordering via `utls.ShuffleChromeTLSExtensions`.
* **Post-Quantum Cryptography (`X25519MLKEM768`)**:
  - Configured dual key shares for `X25519MLKEM768` and `X25519`, producing the characteristic multi-packet Initial datagram burst of modern Chrome browsers.
* **BoringSSL GREASE ECH & Brotli Certificate Compression**:
  - Added `utls.BoringGREASEECH()` extension and `utls.CertCompressionBrotli` certificate compression algorithm.

### 2.4 Chaos Initial Packet Shaping & Packet Coalescing (`packet_packer_chaos.go`, `packet_packer.go`)
* **Chaos Padding Patterns**:
  - Implemented randomized Initial packet padding distributions matching Chrome's wire traffic patterns.
* **Initial + Handshake Coalesced Framing**:
  - Aligned packet coalescing rules with Chrome's client behavior when sending early data and crypto frames across epoch boundaries.

### 2.5 Pluggable Congestion Control Interface (`congestion/interface.go`, `monotime/time.go`)
* **Extensible Congestion Architecture**:
  - Exported pluggable congestion control interfaces (`SendAlgorithm`, `Bandwidth`, `ByteCount`) enabling integration of external controllers (e.g. TCP Brutal v2, BBR, Hysteria pacing).
* **Monotonic Time Helpers**:
  - Added high-resolution monotonic time abstractions (`monotime.Now()`, `monotime.Since()`).

### 2.6 Transport GSO Disablement & Initial Packet Size Introspection (`transport.go`, `connection.go`)
* **Generic Segmentation Offload Disablement (`Transport.DisableGSO`)**:
  - Added `DisableGSO` on `quic.Transport` to bypass UDP GSO on virtual interfaces or buggy kernel drivers that corrupt multi-segment datagrams.
* **Initial Packet Size Introspection (`Conn.InitialPacketSize()`)**:
  - Exposed connection initial packet size for accurate bandwidth estimator and pacing initialization.

### 2.7 Migration to `github.com/metacubex/utls` (`go.mod`, `tls_conn_utls.go`, `chrome_client_hello.go`)
* **Dependency Unification**:
  - Replaced legacy `github.com/refraction-networking/utls` with `github.com/metacubex/utls` (`zhfreal/utls`), ensuring consistent Post-Quantum ML-KEM handling, reality fallback hooks, and session ticket validation across the workspace.

---

## 3. Bug Fixes & Concurrency Remediations (Type 2)

### 3.1 `QUICErrorEvent` Fatal Panic Elimination in uTLS Adapter (`internal/handshake/tls_conn_utls.go`, `quic_event_go126.go`, `quic_event_go125.go`)
* **Defect**:
  - In `utls-mine`, when a handshake error occurs, `UQUICConn.NextEvent()` emits `utls.QUICErrorEvent` (event kind `9`).
  - `utlsQUICConn.NextEvent()` lacked a handler for kind `9`, falling through to `default:` and causing a fatal panic:
    `panic: handshake BUG: unexpected uTLS QUIC event kind 9`.
* **Remediation**:
  - Added `newQUICErrorEvent(err error)` across `quic_event_go126.go` (populating `ev.Err`) and `quic_event_go125.go`.
  - Added `case utls.QUICErrorEvent:` to `utlsQUICConn.NextEvent()`, allowing `cryptoSetup.handleEvent()` to gracefully surface handshake errors to the connection supervisor without crashing.

### 3.2 Defensive Nil-Pointer Teardown Guard (`internal/handshake/tls_conn_utls.go`)
* **Defect**:
  - Calling `Close()` on a nil or partially initialized `utlsQUICConn` resulted in a nil-pointer panic.
* **Remediation**:
  - Added defensive guards `if c == nil || c.conn == nil { return nil }` in `utlsQUICConn.Close()`.

### 3.3 ConnectionState Metadata Loss Remediation (`internal/handshake/tls_conn_utls.go`)
* **Defect**:
  - `utlsQUICConn.ConnectionState()` previously dropped `CurveID` and `ECHAccepted`, preventing callers from verifying whether post-quantum curves or Encrypted Client Hello were negotiated.
* **Remediation**:
  - Added explicit forwarding for `CurveID: tls.CurveID(s.CurveID)` and `ECHAccepted: s.ECHAccepted`.

### 3.4 Chrome Parrot Packet Number Length & Initial ACK Coalescing Fixes (`packet_packer.go`, `packet_packer_chaos.go`)
* **Defect**:
  - Early implementations of Chrome packet coalescing miscalculated Initial ACK frame offsets and packet number lengths when splitting datagrams across MTU limits.
* **Remediation**:
  - Corrected packet number encoding lengths and Initial ACK coalescing logic in `packet_packer.go` to maintain strict compliance with RFC 9000 and Chrome client traces.

### 3.5 Strict Validation for Unsupported TLS Configurations (`internal/handshake/tls_conn_utls.go`)
* **Defect**:
  - Calling `VerifyConnection` with uTLS would fail silently or panic because uTLS cannot produce standard `crypto/tls.ConnectionState` instances for user callbacks.
* **Remediation**:
  - Added upfront validation in `utlsConfigFromStd` explicitly returning clear errors if unsupported callbacks (`VerifyConnection`, `GetConfigForClient`, server certificates) are supplied to `ChromeParrot`.

### 3.6 Transport Parameter Varint Decomposition & Roundtrip Integrity (`internal/handshake/tls_conn_utls.go`)
* **Defect**:
  - Preset uTLS ClientHello extensions bypass internal transport parameter serialization.
* **Remediation**:
  - Implemented `splitTransportParameters()` to parse marshaled transport parameters into structured `FakeQUICTransportParameter` pairs, setting `qtp.TransportParameters` and validating exact roundtrip equivalence against `params`.

### 3.7 Rejection of Ed25519 Servers by Parroted Clients (`integrationtests/self/chrome_parrot_test.go`)
* **Remediation**:
  - Documented and verified that `ChromeParrot` clients omit Ed25519 from `signature_algorithms` (matching real Chrome), cleanly aborting when encountering Ed25519-only servers without hanging or panicking.

### 3.8 Comprehensive uTLS Adapter Unit Test Suite (`internal/handshake/tls_conn_utls_test.go`)
* **Coverage**:
  - Created exhaustive unit tests covering standard config translation, unsupported field rejections, client certificate forwarding, varint splitting and roundtrip validation, connection lifecycle, and `QUICErrorEvent` propagation.

---

## 4. Modified Files Breakdown Matrix

| File Path | Type | Category | Summary of Changes |
| :--- | :--- | :--- | :--- |
| `chrome_parrot.go` | **Added** | **Type 1** | Chrome parrot transport parameter overrides and `ZeroLengthConnectionIDGenerator`. |
| `config.go` | **Modified** | **Type 1** | Integrated `ChromeParrot` field and default validation into `Config`. |
| `interface.go` | **Modified** | **Type 1** | Exported `ChromeParrot` configuration option. |
| `connection.go` | **Modified** | **Type 1 & 2** | Wired chaos packet packer and initial crypto stream handling for Chrome parroting. |
| `crypto_stream.go` | **Modified** | **Type 1** | Initial crypto stream buffering and packet size tracking. |
| `packet_packer.go` | **Modified** | **Type 1 & 2** | Coalesced packet packing and Initial ACK frame placement fixes. |
| `packet_packer_chaos.go` | **Added** | **Type 1 & 2** | Chaos packet padding distribution and ChromeInitial packing logic. |
| `packet_packer_chaos_test.go` | **Added** | **Test** | Unit tests for chaos packet packing and padding boundaries. |
| `congestion/interface.go` | **Added** | **Type 1** | Pluggable congestion controller interface abstractions. |
| `monotime/time.go` | **Added** | **Type 1** | High-resolution monotonic clock utility. |
| `transport.go` | **Modified** | **Type 1** | Added `Transport.DisableGSO` to bypass kernel UDP GSO. |
| `internal/handshake/chrome_client_hello.go` | **Added** | **Type 1** | Chrome QUIC ClientHello specification with `X25519MLKEM768` and GREASE ECH. |
| `internal/handshake/tls_conn_utls.go` | **Added** | **Type 1 & 2** | uTLS `UQUICConn` adapter, `QUICErrorEvent` handling, nil safety, and `ConnectionState` metadata. |
| `internal/handshake/tls_conn_utls_test.go` | **Added** | **Test** | Complete unit test suite for uTLS adapter and transport parameter parsing. |
| `internal/handshake/quic_event_go126.go` | **Modified** | **Type 2** | Added `newQUICErrorEvent()` for Go 1.26+ error event propagation. |
| `internal/handshake/quic_event_go125.go` | **Modified** | **Type 2** | Added backward-compatible `newQUICErrorEvent()` stub for Go 1.25. |
| `internal/wire/transport_parameters_chrome.go`| **Added** | **Type 1** | Chrome transport parameters marshaler with shuffling and GREASE versioning. |
| `internal/wire/grease_quic_version.go` | **Added** | **Type 1** | RFC 9368 GREASE version generator. |
| `integrationtests/self/chrome_parrot_test.go`| **Added** | **Test** | Live integration tests for ChromeParrot handshake, transport parameters, and Ed25519 rejection. |
| `go.mod` / `go.sum` | **Modified** | **Type 1** | Updated dependency to `github.com/metacubex/utls v1.9.0-patch13` (replaced with `github.com/zhfreal/utls v1.9.0-patch13`). |

