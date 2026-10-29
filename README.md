<p align="center">
  <a href="https://sphereon.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://sphereon.com/content/themes/sphereon/assets/img/logo-wit.svg">
      <source media="(prefers-color-scheme: light)" srcset="https://avatars.githubusercontent.com/u/33261381?s=200&v=4">
      <img alt="Sphereon" src="https://avatars.githubusercontent.com/u/33261381?s=200&v=4" width="120">
    </picture>
  </a>
</p>

<h1 align="center">Identity Development Kit (IDK)</h1>

<p align="center">
  <strong>A Kotlin Multiplatform SDK for Digital Identity</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Kotlin-2.3+-7F52FF.svg?logo=kotlin&logoColor=white" alt="Kotlin">
  <img src="https://img.shields.io/badge/Platforms-Android%20%7C%20iOS%20%7C%20JVM%20%7C%20JS%20%7C%20wasmJs%20%7C%20Linux-brightgreen.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/Version-0.26.0--SNAPSHOT-orange.svg" alt="Version">
</p>

<p align="center">
  <a href="#features">Features</a> &nbsp;&bull;&nbsp;
  <a href="#quick-start">Quick Start</a> &nbsp;&bull;&nbsp;
  <a href="#library-modules">Modules</a> &nbsp;&bull;&nbsp;
  <a href="#services">Services</a> &nbsp;&bull;&nbsp;
  <a href="#documentation">Docs</a> &nbsp;&bull;&nbsp;
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

IDK is an open-core Kotlin Multiplatform SDK for digital identity. It covers credential issuance and verification, identity proofing, trust establishment, and secure data exchange. One codebase compiles to Android, iOS, JVM, JavaScript (browser and Node.js), WebAssembly, and Linux native.

You can use IDK on its own to build wallets, verifiers, issuers, and identity services. It also serves as the foundation under Sphereon's commercial [Enterprise Development Kit (EDK)](https://docs.sphereon.com/edk/guides/getting-started).

Full documentation: [docs.sphereon.com/idk](https://docs.sphereon.com/idk/introduction).

---

## Features

Each item links to its guide on the documentation site.

<table>
<tr>
<td width="50%">

**[Decentralized Identifiers (DIDs)](https://docs.sphereon.com/idk/guides/did/overview)**
- Create, [resolve](https://docs.sphereon.com/idk/guides/did/resolution), and [manage](https://docs.sphereon.com/idk/guides/did/management) W3C DIDs
- Pluggable DID method support
- Built-in: `did:key`, `did:jwk`, `did:web`

**[Mobile Documents (mDoc / mDL)](https://docs.sphereon.com/idk/guides/mdoc/overview)**
- ISO/IEC 18013-5 compliant
- [BLE](https://docs.sphereon.com/idk/guides/mdoc/transports/ble), [NFC](https://docs.sphereon.com/idk/guides/mdoc/transports/nfc), and [HTTP/WebSocket](https://docs.sphereon.com/idk/guides/mdoc/transports/http-websocket) transports
- [Engagement](https://docs.sphereon.com/idk/guides/mdoc/engagement/intro) and [transfer](https://docs.sphereon.com/idk/guides/mdoc/transfer/transfer-manager) managers
- Reader and holder functionality

**[Cryptographic Services](https://docs.sphereon.com/idk/guides/crypto/key-management)**
- [JOSE / COSE](https://docs.sphereon.com/idk/guides/crypto/cose-jose) (JWS, JWE, JWT)
- [Signing and verification](https://docs.sphereon.com/idk/guides/crypto/signing-verification)
- Pluggable [KMS providers](https://docs.sphereon.com/idk/guides/crypto/kms-providers): software, AWS, Azure, mobile keystores
- [Identifier resolution](https://docs.sphereon.com/idk/guides/crypto/identifier-resolution) (DID, x5c, JWK)

**[Trust Management](https://docs.sphereon.com/idk/guides/trust/overview)**
- [ETSI trust lists](https://docs.sphereon.com/idk/guides/trust/etsi-trust-lists)
- [X.509 certificate validation](https://docs.sphereon.com/idk/guides/trust/certificate-validation)
- [DID-based trust](https://docs.sphereon.com/idk/guides/trust/did-trust)
- [OpenID Federation](https://docs.sphereon.com/idk/guides/trust/openid-federation)

</td>
<td width="50%">

**[OpenID for Verifiable Presentations (OID4VP)](https://docs.sphereon.com/idk/guides/oid4vp/overview)**
- [Holder](https://docs.sphereon.com/idk/guides/oid4vp/holder) and [verifier](https://docs.sphereon.com/idk/guides/oid4vp/verifier) implementations
- [DCQL query language](https://docs.sphereon.com/idk/guides/oid4vp/dcql)
- [Universal request handling](https://docs.sphereon.com/idk/guides/oid4vp/universal)

**[OpenID for Verifiable Credential Issuance (OID4VCI)](https://docs.sphereon.com/idk/guides/oid4vci/overview)**
- [Issuer](https://docs.sphereon.com/idk/guides/oid4vci/issuer) and [holder](https://docs.sphereon.com/idk/guides/oid4vci/holder) implementations
- Authorization code, pre-authorized code, deferred issuance
- Notification endpoint

**[SD-JWT](https://docs.sphereon.com/idk/guides/sdjwt/overview)**
- [Selective disclosure issuance](https://docs.sphereon.com/idk/guides/sdjwt/issuance)
- Verification, key binding, status lists

**[OAuth 2.0 / OpenID Connect](https://docs.sphereon.com/idk/guides/oauth2/client)**
- [OAuth2 client](https://docs.sphereon.com/idk/guides/oauth2/client)
- [Authorization server](https://docs.sphereon.com/idk/guides/oauth2/authorization-server) (auth-code, client-credentials, pre-authorized-code, token exchange, introspection, revocation, PAR)
- [DPoP and PKCE](https://docs.sphereon.com/idk/guides/oauth2/dpop-pkce)
- [JWT validation](https://docs.sphereon.com/idk/guides/oauth2/jwt-validation)

**[Identity Proofing and Reconciliation](https://docs.sphereon.com/idk/guides/identity/overview)**
- Document verification, biometrics, OTP
- Policy-driven [identity reconciliation](https://docs.sphereon.com/idk/guides/identity/overview)

**[Developer Experience](https://docs.sphereon.com/idk/guides/di/scopes)**
- Compile-time [dependency injection](https://docs.sphereon.com/idk/guides/di/app-setup) via [Metro](https://github.com/ZacSweers/metro)
- [Configuration system](https://docs.sphereon.com/idk/guides/config/configuration) with [multi-tenancy](https://docs.sphereon.com/idk/guides/config/multi-tenancy)
- [Event system](https://docs.sphereon.com/idk/guides/core/events), [scoped logging](https://docs.sphereon.com/idk/guides/core/logging/overview)
- [Ktor](https://docs.sphereon.com/idk/guides/http/ktor) integration

</td>
</tr>
</table>

---

## Supported Platforms

| Platform | Status | Notes |
|:---------|:------:|:------|
| JVM | Supported | Java 21+ |
| Android | Supported | API 27+ (Android 8.1+); BLE, NFC HCE, Android Keystore |
| iOS | Supported | arm64, x64, simulator-arm64; CoreBluetooth, CoreNFC, Secure Enclave |
| JavaScript | Supported | Browser and Node.js, ES modules, TypeScript definitions generated |
| WebAssembly | Supported | wasmJs (browser and Node.js), BigInt, TypeScript definitions |
| Linux | Supported | x64, server and CLI tooling |

See [Platform Setup](https://docs.sphereon.com/idk/guides/platform-setup) for per-platform requirements.

---

## Quick Start

Full installation and getting-started instructions: [docs.sphereon.com/idk/guides/getting-started](https://docs.sphereon.com/idk/guides/getting-started).

### Prerequisites

- JDK 21 or higher
- Gradle 9.x (wrapper included)
- Android SDK, compileSdk 35 (for Android targets)
- Xcode 15+ (for iOS targets, macOS only)

### Installation

Add the Sphereon Maven repository and dependencies to your `build.gradle.kts`:

```kotlin
repositories {
    mavenCentral()
    maven("https://nexus.sphereon.com/repository/sphereon-opensource-releases/")
    maven("https://nexus.sphereon.com/repository/sphereon-opensource-snapshots/")
}

dependencies {
    // Core API — pin with platformVersion from platform-version.properties
    implementation("com.sphereon.idk:lib-core-api-public:${platformVersion}")

    // Cryptography
    implementation("com.sphereon.idk:lib-crypto-core-public:${platformVersion}")
    implementation("com.sphereon.idk:lib-crypto-core-impl:${platformVersion}")

    // DIDs
    implementation("com.sphereon.idk:lib-did-resolver-impl:${platformVersion}")
    implementation("com.sphereon.idk:lib-did-methods-key:${platformVersion}")

    // mDoc
    implementation("com.sphereon.idk:lib-mdoc-core-public:${platformVersion}")
    implementation("com.sphereon.idk:lib-mdoc-core-impl:${platformVersion}")

    // OID4VCI / OID4VP / SD-JWT: add as needed
}
```

`platformVersion` is defined in [`platform-version.properties`](platform-version.properties) at the repo root (loaded by `settings.gradle.kts` into every project's `version`).

See the [installation guide](https://docs.sphereon.com/idk/guides/installation) for per-platform setup and the [modules reference](https://docs.sphereon.com/idk/guides/modules) for the full module catalog.

### npm packages

JavaScript and WebAssembly artefacts are published to npmjs under the `@sphereon/idk-*` scope. For example:

```bash
npm install @sphereon/idk-lib-core-api-public
```

Snapshots use the `snapshot` dist-tag (`@sphereon/idk-foo@snapshot`); released versions are on `latest`.

Each package is self-contained: the Kotlin/JS runtime modules it imports (`kotlin-stdlib`, `ktor`, `kotlinx-*`, ...) ship inside the package under `idk-runtime/`, so installing the `-public` and `-impl` packages you use is enough, with no extra runtime packages and no bootstrap package. The only external dependencies are the regular npm packages listed in each `package.json`. The staging is done by [`gradle/idk-npm-runtime.gradle.kts`](gradle/idk-npm-runtime.gradle.kts), which also fails the package assembly if an import would not resolve inside the package.

### Building from Source

```bash
git clone https://github.com/Sphereon-Opensource/Identity-Development-Kit.git
cd Identity-Development-Kit
./gradlew build                     # full multiplatform build
./gradlew build -Dkmp.targets=jvm   # JVM only (~5 min)
./gradlew allTests                  # run all tests
```

On Windows, run `./gradlew --stop` before rebuilding if you hit file-locking errors.

---

## Library Modules

Modules follow the `lib-<domain>-<feature>-{public,impl}` convention. `public` modules contain interfaces and data models; `impl` modules contain implementations.

Full module reference: [docs.sphereon.com/idk/guides/modules](https://docs.sphereon.com/idk/guides/modules).

<details>
<summary><b>Core</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-core-api-public` | Core interfaces, `IdkResult`, command pattern, error types, tracing |
| `lib-core-api-default` | Default implementations of core APIs |
| `lib-core-events-public` / `-impl` | [Event system](https://docs.sphereon.com/idk/guides/core/events) for pub/sub |
| `lib-core-loggers-mobile-logger` | Mobile-friendly logger sink |
| `lib-conf-settings` | Multiplatform [configuration management](https://docs.sphereon.com/idk/guides/config/configuration) |
| `lib-conf-yaml` | YAML config source |

</details>

<details>
<summary><b>Cryptography</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-crypto-core-public` / `-impl` | Core crypto operations, JWS, JWE, JWT |
| `lib-crypto-kms-provider-software` | Software-based key storage (ephemeral) |
| `lib-crypto-kms-provider-aws` | AWS KMS integration |
| `lib-crypto-kms-provider-azure` | Azure Key Vault / HSM integration |
| `lib-crypto-kms-provider-mobile` | iOS Keychain / Android Keystore |
| `services-kms-rest` | Ktor wiring a KMS host embeds; the hosting assembly mounts the tenant typed KMS resource surface |

</details>

<details>
<summary><b>Decentralized Identifiers (DID)</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-did-core-public` | DID data models and interfaces |
| `lib-did-resolver-public` / `-impl` | Universal DID resolver |
| `lib-did-manager-public` / `-impl` | DID lifecycle management |
| `lib-did-methods-key` | `did:key` method support |
| `lib-did-methods-jwk` | `did:jwk` method support |
| `lib-did-methods-web` | `did:web` method support |
| `lib-did-persistence-memory` | In-memory DID storage |
| `lib-did-persistence-sqlite` | SQLite DID storage |

</details>

<details>
<summary><b>Mobile Documents (mDoc / mDL)</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-mdoc-core-public` / `-impl` | ISO/IEC 18013-5 mDoc parsing and creation |
| `lib-mdoc-datatransfer` | Device engagement and session handling |
| `lib-mdoc-transport-ble` | Bluetooth Low Energy transport |
| `lib-mdoc-transport-nfc` | NFC transport (Android) |
| `lib-mdoc-transport-oid4vp` | OID4VP transport integration |
| `lib-mdoc-reader` | mDoc reader/verifier functionality |

</details>

<details>
<summary><b>OpenID4VP / OpenID4VCI / OAuth2</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-openid-oid4vp-common-public` | Shared OID4VP types |
| `lib-openid-oid4vp-holder-public` / `-impl` | Wallet/holder OID4VP support |
| `lib-openid-oid4vp-verifier-public` / `-impl` | Verifier OID4VP support |
| `lib-openid-oid4vp-dcql` | DCQL query language |
| `lib-openid-oid4vci-common-public` | Shared OID4VCI types |
| `lib-openid-oid4vci-holder-public` / `-impl` | Holder OID4VCI flow |
| `lib-openid-oid4vci-issuer-public` / `-impl` | Issuer OID4VCI flow |
| `lib-oauth2-client-public` / `-impl` | OAuth2 client implementation |
| `lib-oauth2-server-authorization-public` / `-impl` | OAuth2 authorization server |
| `lib-oauth2-server-resource-public` / `-impl` | OAuth2 resource server |
| `lib-oauth2-jwt-validation-api` / `-impl` | JWT validation utilities |

</details>

<details>
<summary><b>SD-JWT</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-sdjwt-public` / `-impl` | Selective Disclosure JWT |

</details>

<details>
<summary><b>Identity Proofing</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-identity-resolution-public` / `-impl` | Identity resolution and lookup |
| `lib-identity-matching-public` / `-impl` | Probabilistic identity matching |
| `lib-identity-reconciliation-public` / `-impl` | Policy-driven reconciliation |
| `lib-identity-idv-public` / `-impl` | Identity verification orchestration |

</details>

<details>
<summary><b>Data Link / Transport</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-data-link-ble` | BLE communication layer |
| `lib-data-link-nfc` | NFC communication layer |
| `lib-data-link-http-client-public` / `-impl` | [HTTP client abstraction](https://docs.sphereon.com/idk/guides/http/http-client) |

</details>

<details>
<summary><b>Storage</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-data-store-kv-public` / `-impl` | [Key-value storage](https://docs.sphereon.com/idk/guides/data-store/key-value-store) abstraction |
| `lib-data-store-kv-impl-memory` | In-memory KV store |
| `lib-data-store-kv-impl-kottage` | Persistent KV store (Kottage) |
| `lib-data-store-blob-public` / `-impl-fs` | [Blob storage](https://docs.sphereon.com/idk/guides/data-store/blob-store) (filesystem) |
| `lib-data-store-party-public` / `-impl` | [Party / tenant data models](https://docs.sphereon.com/idk/guides/data-store/party-management) |

</details>

<details>
<summary><b>Trust</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-trust-etsi` | ETSI trust list support |
| `lib-trust-etsi-entities-public` | ETSI entities models |
| `lib-trust-x509` | X.509 certificate trust |
| `lib-trust-did` | DID-based trust |
| `lib-trust-oidfed` | OpenID Federation |

</details>

<details>
<summary><b>Credential Design</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-credential-claims-mapper-public` / `-impl` | Claim mapping for credential payloads |
| `lib-data-store-credential-design-public` / `-impl` | [Credential design](https://docs.sphereon.com/idk/guides/credential-design/overview) registry |

</details>

<details>
<summary><b>Server / Integration</b></summary>

| Module | Description |
|:-------|:------------|
| `ktor-server-kotlin-inject` | [Ktor + Metro DI integration](https://docs.sphereon.com/idk/guides/http/ktor) |

</details>

<details>
<summary><b>CBOR</b></summary>

| Module | Description |
|:-------|:------------|
| `lib-cbor-public` / `-impl` | [CBOR encoding/decoding](https://docs.sphereon.com/idk/guides/cbor) |

</details>

---

<!-- generated:module-index:start product=idk -->
<!-- regenerate: node tooling/module-docs/gen-readme.mjs --product idk; edit docs/module-index/, not this section -->

## Module index

218 modules across 49 domains, generated from the verified module index (`docs/module-index/`): every abstract below passed the four-facet rubric, 44 checks per module.
Full narratives: [Module Reference](https://docs.sphereon.com/idk/guides/modules).

| Domain | Modules | Scope |
|---|---:|---|
| attribute | 2 | `attribute` provides flow-agnostic attribute wiring primitives. `attribute-flow-public` defines `AttributeBag`, `AttributePath`, and related flow-agnostic structures; `attribute-mapping-public` provides generic source→target attribute rename rules and an applier, reused across connectors and presentation flows. |
| catalog | 8 | `catalog` manages **TS 11 attestation catalogs** (European eIDAS / trusted-list style catalogs). |
| cbor | 2 | `cbor` implements the CBOR data model and runtime (RFC 8949), split into public API and impl. |
| compression | 1 | Single-module domain: `lib-compression` provides GZIP / zlib / raw DEFLATE compression primitives used by status lists, JWE `zip` handling, and other compressed payloads. |
| conf-settings | 1 | Single-module domain: `lib-conf-settings` — a `multiplatform-settings`-backed property source for configuration, usable on mobile/browser targets where file-based config is not available. |
| conf-theme | 5 | `conf-theme` manages branding and theme metadata: core model/runtime (public/impl), Compose Multiplatform bindings (`lib-conf-theme-compose`), CSS token bindings for web UIs (`lib-conf-theme-web`), and a client module (`lib-conf-theme-client`). |
| conf-yaml | 1 | Single-module domain: `lib-conf-yaml` — YAML property sources for app, tenant, and principal scopes. |
| core | 7 | `core` is the shared foundation every IDK module builds on: result monad + command hierarchy + configuration + logging + HTTP adapter + caching + auth contracts (`lib-core-api-public`, with `lib-core-api-default` as the default DI-wired runtime), typed application event hub (`lib-core-events-*`), IDNA/Punycode support (`lib-core-idn-public`, RFC 3492 + IDNA2008), compat annotations for JS exports, and an on-device mobile logger. |
| credential | 2 | `credential` holds the credential **claims mapper**: a public/impl pair that maps and normalizes claims between credential representations (e.g. |
| crypto-certificate | 2 | `crypto-certificate` is the tenant-aware **certificate reference store**, parallel to `crypto-key`: the API module defines how X.509 certificate references (not the private keys) are recorded per tenant; the sqlite module provides the durable SQLDelight-backed implementation. |
| crypto-core | 3 | `crypto-core` is the foundational COSE/JOSE crypto layer for IDK: algorithms, codecs, signing/verification command skeletons, and shared key types. |
| crypto-data-integrity-proof | 5 | `crypto-data-integrity-proof` implements **W3C Verifiable Credentials Data Integrity 1.0** proof suites. |
| crypto-key | 3 | `crypto-key` is the tenant-aware **key reference store**: it persists pointers/references to keys (ids, tenant, provider metadata) — **not key material itself**. |
| crypto-kms | 6 | `crypto-kms` is the Key Management Service abstraction: a provider SPI plus four concrete providers and a REST-facing API. |
| crypto-secdsa | 2 | `crypto-secdsa` provides Elliptic-Curve Digital Signature Algorithm support split into a public API surface (`lib-crypto-secdsa-public`) and an implementation module (`lib-crypto-secdsa-impl`). |
| data | 4 | `data` covers credential-definition data and cross-cutting integration taxonomy. |
| data-link | 7 | `data-link` provides transport/link primitives used across mDoc and wallet flows: HTTP client (public/impl), BLE (public), and NFC APDU/NDEF (public/impl). |
| data-store-asset | 2 | `data-store-asset` is a tenant asset library: content-addressed, per-tenant deduplicated asset storage (public API + impl). |
| data-store-blob | 7 | `data-store-blob` is the cross-cutting blob/object storage abstraction: public contracts plus multiple backings — memory, filesystem (`impl-fs`), key-value (`impl-kv`), OKD (`impl-okd`), and an HTTP client (`client-http`) for remote blob services. |
| data-store-credential-design | 2 | `data-store-credential-design` stores credential design, localization, and render metadata (public/impl): how a credential type is presented (layout, branding, localized labels) independent of the wire format. |
| data-store-credential-type-binding | 2 | `data-store-credential-type-binding` is a role-independent registry mapping a semantic attribute set to a credential wire-format identity (public/impl). |
| data-store-kv | 5 | `data-store-kv` is the cross-cutting key-value storage abstraction: public contracts with backings for memory, Kottage, and Android-protected storage (`impl-android-protected`). |
| data-store-okd-openapi | 1 | Single-module domain: `lib-data-store-okd-openapi` — OpenAPI types for OKD (Onderwijs Koppeling voor Document Management), the Dutch MBO education document-management standard. |
| data-store-okd-server | 1 | Single-module domain: `lib-data-store-okd-server` — server-side integration for OKD (Dutch MBO) document storage, pairing with `okd-openapi` types and `blob-impl-okd` backing. |
| data-store-party | 1 | Single-module domain: `lib-data-store-party-public` — shared data models for identity, contact, and tenant (the “party” concept) plus filter/pagination models reused across stores. |
| data-store-schema-registry | 2 | `data-store-schema-registry` provides versioned schema management backed by a blob store (public/impl): schemas are stored as blobs with version metadata on top. |
| data-store-vault | 2 | `data-store-vault` defines a provider-neutral protected file/folder contract (public) plus a portability module (`lib-data-store-vault-portability`) for moving vault content across providers/backends. |
| did | 18 | `did` is the W3C Decentralized Identifier domain: the largest IDK domain (18 modules). |
| identity | 11 | `identity` groups four capabilities: **matching** (hashed/encrypted identifier matching), **resolution** (identity resolution), **reconciliation** (cross-source attribute reconciliation) — each as public/impl — plus **IDV** (identity verification): a public API with two drivers, `lib-idv-oidc` (OIDC IDP-based verification) and `lib-idv-wallet` (wallet-based verification). |
| jsonld | 4 | `jsonld` provides JSON-LD 1.1 capability with a two-track design: Track A — loader + validators (`lib-jsonld-loader`, shared public surface); Track B — full processor (`lib-jsonld-processor`). `lib-jsonld-rdf-canon` implements RDF canonicalization (URDNA2015 class algorithms) needed for Data Integrity proofs. |
| mdoc | 13 | `mdoc` implements ISO 18013 mobile driving license (mDoc) support: document model and CBOR codecs (`core` public/impl), device-engagement orchestration (`datatransfer` public/impl), reader runtime (`lib-mdoc-reader`), and four transports — BLE (public/impl), NFC engagement/handover, REST API, and OID4VP for ISO 18013-7 online flows. |
| oauth2 | 12 | `oauth2` implements the OAuth2/OIDC stack: shared models (common public/impl), OAuth2 client (with JAR, PAR, token exchange), Authorization Server command graph, Resource Server validation/introspection/DPoP caches, JWT + OIDC discovery validation (api/impl), and a REST-facing server module (`lib-oauth2-server-rest`). |
| openid-oid4vc | 2 | `openid-oid4vc` holds shared OpenID for Verifiable Credential family types and a QR code service (public/impl), used by both OID4VCI and OID4VP. |
| openid-oid4vci | 9 | `openid-oid4vci` implements OpenID for Verifiable Credential Issuance: common model and validators, **issuer** runtime, **holder** (wallet) runtime, and a REST-facing issuer service layer (`rest-public`/`rest-impl` plus `issuer-rest`). |
| openid-oid4vp | 16 | `openid-oid4vp` implements OpenID for Verifiable Presentations (16 modules): common request types, **holder** and **verifier** runtimes (plus a VCDM-specific verifier impl), **DCQL** query/response types and a DCQL store (public/impl/rest with `oid4vp-dcql` REST spec), a **universal** verifier service layer (`oid4vp-universal` REST spec), and an **auth-bridge** that maps OID4VP flows onto traditional authentication. `oid4vp-universal`. |
| sdjwt | 2 | `sdjwt` implements IETF SD-JWT (Selective Disclosure JWT) issuer, holder, and verifier commands as a public/impl pair. |
| services-did | 2 | Deployable Ktor REST servers for DID: `services-did-hosting-rest` (DID hosting, REST spec `did-hosting`) and `services-did-manager-rest` (DID lifecycle management API). |
| services-kms | 1 | Single-module domain: `services-kms-rest` — Ktor wiring a KMS host embeds (per-request DI, JSON negotiation, liveness). |
| services-ktor | 2 | Ktor server build plugins: `ktor-server-jwt-auth` (JWT auth plugin) and `ktor-server-kotlin-inject` (bridges Metro dependency graphs into request handling — artifact name retained from pre-Metro codebase for compatibility). |
| services-oauth2-as | 1 | Single-module domain: `services-oauth2-as-rest` — deployable OAuth2/OIDC Authorization Server (Ktor), REST spec `platform-admin`. |
| services-oid4vci-issuer | 1 | Single-module domain: `services-oid4vci-issuer-rest` — deployable OID4VCI issuer server (Ktor), REST specs `oid4vci-issuer` and `oid4vci-issuer-session`. |
| services-oid4vp-verifier | 1 | Single-module domain: `services-oid4vp-verifier-rest` — deployable OID4VP verifier server (Ktor), REST spec `oid4vp-verifier`. |
| services-statuslist | 1 | Single-module domain: `services-statuslist-rest` — public, unauthenticated token-hosting REST that serves the signed JWT/CWT status list token (open-core, so lives in IDK). |
| software | 2 | `software` defines a unified **software-instance model** with read/write SPIs (`lib-software-registry-public`) and its implementation (`lib-software-registry-impl`). |
| statuslist | 2 | `statuslist` implements credential status lists covering both **IETF Token Status List** and **W3C Bitstring Status List** (public API carries a `wallet-unit` REST spec). |
| trust | 7 | `trust` implements trust validation across multiple frameworks: core (entity discovery, trust-anchor refresh, revocation) public/impl; **ETSI** LOTL trust-list support (`lib-trust-etsi` + `lib-trust-etsi-entities-public`); **X.509** trust validation (`lib-trust-x509`); **DID**-based trust validation (`lib-trust-did`); and **OpenID Federation** trust validation (`lib-trust-oidfed`). |
| ui | 2 | `ui` provides shared Compose Multiplatform UI component token primitives (`lib-ui-compose`) and a blob adapter (`lib-ui-compose-blob-adapter`) for rendering blob-backed content in Compose UIs. |
| versions | 1 | Single-module domain: `idk-bom` — the Bill-of-Materials that pins IDK library versions for consumers (EDK, VDX, external adopters) so they can import one BOM instead of per-module versions. |
| wallet | 22 | `wallet` is the largest IDK domain (22 modules): the protocol-neutral headless wallet runtime and SDK. |

<details>
<summary><b>Module ids by domain (218)</b></summary>

- **attribute**: `lib-attribute-flow-public`, `lib-attribute-mapping-public`
- **catalog**: `lib-catalog-eu-impl`, `lib-catalog-eu-public`, `lib-catalog-impl`, `lib-catalog-persistence-api`, `lib-catalog-persistence-memory`, `lib-catalog-persistence-sqlite`, `lib-catalog-public`, `lib-catalog-ts11-public`
- **cbor**: `lib-cbor-impl`, `lib-cbor-public`
- **compression**: `lib-compression`
- **conf-settings**: `lib-conf-settings`
- **conf-theme**: `lib-conf-theme-client`, `lib-conf-theme-compose`, `lib-conf-theme-core-impl`, `lib-conf-theme-core-public`, `lib-conf-theme-web`
- **conf-yaml**: `lib-conf-yaml`
- **core**: `lib-core-api-default`, `lib-core-api-public`, `lib-core-compat-annotations`, `lib-core-events-impl`, `lib-core-events-public`, `lib-core-idn-public`, `lib-core-loggers-mobile-logger`
- **credential**: `lib-credential-claims-mapper-impl`, `lib-credential-claims-mapper-public`
- **crypto-certificate**: `lib-crypto-certificate-persistence-api`, `lib-crypto-certificate-persistence-sqlite`
- **crypto-core**: `lib-crypto-core`, `lib-crypto-core-impl`, `lib-crypto-core-public`
- **crypto-data-integrity-proof**: `lib-crypto-data-integrity-proof-ecdsa-rdfc-2019`, `lib-crypto-data-integrity-proof-eddsa-jcs-2022`, `lib-crypto-data-integrity-proof-eddsa-rdfc-2022`, `lib-crypto-data-integrity-proof-impl`, `lib-crypto-data-integrity-proof-public`
- **crypto-key**: `lib-crypto-key-persistence-api`, `lib-crypto-key-persistence-impl`, `lib-crypto-key-persistence-sqlite`
- **crypto-kms**: `lib-crypto-kms-provider-aws`, `lib-crypto-kms-provider-azure`, `lib-crypto-kms-provider-mobile`, `lib-crypto-kms-provider-rest`, `lib-crypto-kms-provider-software`, `lib-crypto-kms-rest-api`
- **crypto-secdsa**: `lib-crypto-secdsa-impl`, `lib-crypto-secdsa-public`
- **data**: `lib-data-credential-definition-impl`, `lib-data-credential-definition-public`, `lib-data-credential-definition-rest`, `lib-data-integration-public`
- **data-link**: `lib-data-link-ble-public`, `lib-data-link-http-client`, `lib-data-link-http-client-impl`, `lib-data-link-http-client-kms-impl`, `lib-data-link-http-client-public`, `lib-data-link-nfc-impl`, `lib-data-link-nfc-public`
- **data-store-asset**: `lib-data-store-asset-impl`, `lib-data-store-asset-public`
- **data-store-blob**: `lib-data-store-blob-client-http`, `lib-data-store-blob-impl`, `lib-data-store-blob-impl-fs`, `lib-data-store-blob-impl-kv`, `lib-data-store-blob-impl-memory`, `lib-data-store-blob-impl-okd`, `lib-data-store-blob-public`
- **data-store-credential-design**: `lib-data-store-credential-design-impl`, `lib-data-store-credential-design-public`
- **data-store-credential-type-binding**: `lib-data-store-credential-type-binding-impl`, `lib-data-store-credential-type-binding-public`
- **data-store-kv**: `lib-data-store-kv-impl`, `lib-data-store-kv-impl-android-protected`, `lib-data-store-kv-impl-kottage`, `lib-data-store-kv-impl-memory`, `lib-data-store-kv-public`
- **data-store-okd-openapi**: `lib-data-store-okd-openapi`
- **data-store-okd-server**: `lib-data-store-okd-server`
- **data-store-party**: `lib-data-store-party-public`
- **data-store-schema-registry**: `lib-data-store-schema-registry-impl`, `lib-data-store-schema-registry-public`
- **data-store-vault**: `lib-data-store-vault-portability`, `lib-data-store-vault-public`
- **did**: `lib-did-core-public`, `lib-did-hosting-impl`, `lib-did-hosting-public`, `lib-did-manager-impl`, `lib-did-manager-public`, `lib-did-methods-jwk`, `lib-did-methods-key`, `lib-did-methods-web`, `lib-did-methods-webvh-provider`, `lib-did-methods-webvh-public`, `lib-did-methods-webvh-resolver`, `lib-did-methods-webvh-rest-server`, `lib-did-persistence-api`, `lib-did-persistence-memory`, `lib-did-persistence-sqlite`, `lib-did-resolver-impl`, `lib-did-resolver-public`, `lib-did-rest-resolver-server`
- **identity**: `lib-identity-matching-impl`, `lib-identity-matching-public`, `lib-identity-reconciliation-impl`, `lib-identity-reconciliation-oidc`, `lib-identity-reconciliation-public`, `lib-identity-resolution-catalog`, `lib-identity-resolution-impl`, `lib-identity-resolution-public`, `lib-idv-oidc`, `lib-idv-public`, `lib-idv-wallet`
- **jsonld**: `lib-jsonld-loader`, `lib-jsonld-processor`, `lib-jsonld-public`, `lib-jsonld-rdf-canon`
- **mdoc**: `lib-mdoc-core`, `lib-mdoc-core-impl`, `lib-mdoc-core-public`, `lib-mdoc-datatransfer`, `lib-mdoc-datatransfer-impl`, `lib-mdoc-datatransfer-public`, `lib-mdoc-reader`, `lib-mdoc-transport-ble`, `lib-mdoc-transport-ble-impl`, `lib-mdoc-transport-ble-public`, `lib-mdoc-transport-nfc`, `lib-mdoc-transport-oid4vp`, `lib-mdoc-transport-restapi`
- **oauth2**: `lib-oauth2-client-impl`, `lib-oauth2-client-public`, `lib-oauth2-common-impl`, `lib-oauth2-common-public`, `lib-oauth2-jwt-validation-api`, `lib-oauth2-jwt-validation-impl`, `lib-oauth2-server-authorization-impl`, `lib-oauth2-server-authorization-public`, `lib-oauth2-server-authorization-theme`, `lib-oauth2-server-resource-impl`, `lib-oauth2-server-resource-public`, `lib-oauth2-server-rest`
- **openid-oid4vc**: `lib-openid-oid4vc-common-impl`, `lib-openid-oid4vc-common-public`
- **openid-oid4vci**: `lib-openid-oid4vci-common-impl`, `lib-openid-oid4vci-common-public`, `lib-openid-oid4vci-holder-impl`, `lib-openid-oid4vci-holder-public`, `lib-openid-oid4vci-issuer-impl`, `lib-openid-oid4vci-issuer-public`, `lib-openid-oid4vci-issuer-rest`, `lib-openid-oid4vci-rest-impl`, `lib-openid-oid4vci-rest-public`
- **openid-oid4vp**: `lib-openid-oid4vp-auth-bridge-impl`, `lib-openid-oid4vp-auth-bridge-public`, `lib-openid-oid4vp-common-impl`, `lib-openid-oid4vp-common-public`, `lib-openid-oid4vp-dcql`, `lib-openid-oid4vp-dcql-store-impl`, `lib-openid-oid4vp-dcql-store-public`, `lib-openid-oid4vp-dcql-store-rest`, `lib-openid-oid4vp-holder-impl`, `lib-openid-oid4vp-holder-public`, `lib-openid-oid4vp-universal-impl`, `lib-openid-oid4vp-universal-public`, `lib-openid-oid4vp-verifier-impl`, `lib-openid-oid4vp-verifier-public`, `lib-openid-oid4vp-verifier-rest`, `lib-openid-oid4vp-verifier-vcdm-impl`
- **sdjwt**: `lib-sdjwt-impl`, `lib-sdjwt-public`
- **services-did**: `services-did-hosting-rest`, `services-did-manager-rest`
- **services-kms**: `services-kms-rest`
- **services-ktor**: `ktor-server-jwt-auth`, `ktor-server-kotlin-inject`
- **services-oauth2-as**: `services-oauth2-as-rest`
- **services-oid4vci-issuer**: `services-oid4vci-issuer-rest`
- **services-oid4vp-verifier**: `services-oid4vp-verifier-rest`
- **services-statuslist**: `services-statuslist-rest`
- **software**: `lib-software-registry-impl`, `lib-software-registry-public`
- **statuslist**: `lib-statuslist-impl`, `lib-statuslist-public`
- **trust**: `lib-trust-core-impl`, `lib-trust-core-public`, `lib-trust-did`, `lib-trust-etsi`, `lib-trust-etsi-entities-public`, `lib-trust-oidfed`, `lib-trust-x509`
- **ui**: `lib-ui-compose`, `lib-ui-compose-blob-adapter`
- **versions**: `idk-bom`
- **wallet**: `lib-wallet-impl`, `lib-wallet-interaction-client-rest`, `lib-wallet-interaction-holder-wiring`, `lib-wallet-interaction-impl`, `lib-wallet-interaction-presenter`, `lib-wallet-interaction-presenter-contracts`, `lib-wallet-interaction-protocol-iso18013`, `lib-wallet-interaction-protocol-oid4vci`, `lib-wallet-interaction-protocol-oid4vp`, `lib-wallet-interaction-public`, `lib-wallet-party-local`, `lib-wallet-party-public`, `lib-wallet-provider-local`, `lib-wallet-provider-public`, `lib-wallet-public`, `lib-wallet-unit-impl`, `lib-wallet-unit-public`, `lib-wallet-wsca-impl`, `lib-wallet-wsca-public`, `lib-wallet-wscd-mobile`, `lib-wallet-wscd-public`, `lib-wallet-wscd-software`

</details>

<!-- generated:module-index:end -->

## Services

IDK ships reference services that wrap the core libraries with HTTP adapters. Each has its own page on the documentation site.

| Service | Module | Documentation |
|:--------|:-------|:--------------|
| KMS host wiring | `services/kms/rest` | [docs.sphereon.com/idk/services/kms](https://docs.sphereon.com/idk/services/kms) |
| Ktor base | `services/ktor` | [docs.sphereon.com/idk/services/ktor](https://docs.sphereon.com/idk/services/ktor) |
| OAuth 2.0 Authorization Server | `services/oauth2-as/rest` | [docs.sphereon.com/idk/services/oauth2-as](https://docs.sphereon.com/idk/services/oauth2-as) |
| OID4VCI Issuer | `services/oid4vci-issuer/rest` | [docs.sphereon.com/idk/services/oid4vci-issuer](https://docs.sphereon.com/idk/services/oid4vci-issuer) |
| OID4VP Verifier | `services/oid4vp-verifier/rest` | [docs.sphereon.com/idk/services/oid4vp-verifier](https://docs.sphereon.com/idk/services/oid4vp-verifier) |

The OID4VCI Holder REST service has moved to the [Enterprise Development Kit](https://docs.sphereon.com/edk). Holder library modules (`lib-openid-oid4vci-holder-*`) remain in IDK.

Services overview: [docs.sphereon.com/idk/services/overview](https://docs.sphereon.com/idk/services/overview).

---

## Architecture

IDK separates APIs from implementations:

```
lib/<domain>/
  ├── public/     # Interfaces, data models, contracts
  └── impl/       # Implementations (swappable)
```

Architecture deep-dive: [docs.sphereon.com/idk/architecture](https://docs.sphereon.com/idk/architecture).

### Error Handling

IDK uses `IdkResult<V, E>` for explicit error handling instead of exceptions:

```kotlin
import com.sphereon.core.api.Ok
import com.sphereon.core.api.Err
import com.sphereon.core.api.error.IdkError

fun createDid(): IdkResult<String, IdkError> {
    return Ok("did:key:z6Mk...")
    // or: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid key type"))
}

when (val result = createDid()) {
    is Ok  -> println("Created: ${result.value}")
    is Err -> println("Failed: ${result.error.message}")
}
```

### Dependency Injection

IDK uses [Metro](https://github.com/ZacSweers/metro) for compile-time DI across all platforms. Metro is a Kotlin compiler plugin and works on every Kotlin Multiplatform target the IDK ships to. See the [DI app-setup guide](https://docs.sphereon.com/idk/guides/di/app-setup) and the [scopes guide](https://docs.sphereon.com/idk/guides/di/scopes).

Scopes: `AppScope` > `UserScope` > `SessionScope`.

---

## Documentation

Full documentation: [docs.sphereon.com/idk](https://docs.sphereon.com/idk/introduction).

| Section | Link |
|:--------|:-----|
| Introduction | [docs.sphereon.com/idk/introduction](https://docs.sphereon.com/idk/introduction) |
| Getting Started | [docs.sphereon.com/idk/guides/getting-started](https://docs.sphereon.com/idk/guides/getting-started) |
| Installation | [docs.sphereon.com/idk/guides/installation](https://docs.sphereon.com/idk/guides/installation) |
| Platform Setup | [docs.sphereon.com/idk/guides/platform-setup](https://docs.sphereon.com/idk/guides/platform-setup) |
| Architecture | [docs.sphereon.com/idk/architecture](https://docs.sphereon.com/idk/architecture) |
| Module Reference | [docs.sphereon.com/idk/guides/modules](https://docs.sphereon.com/idk/guides/modules) |
| Services | [docs.sphereon.com/idk/services/overview](https://docs.sphereon.com/idk/services/overview) |
| FAQ | [docs.sphereon.com/idk/guides/faq](https://docs.sphereon.com/idk/guides/faq) |

### Generating local API docs (Dokka)

```bash
./gradlew dokkaGenerate
```

Output: `build/dokka/html/index.html`. The hosted Dokka build is also linked from the documentation site.

### Build commands

| Command | Description |
|:--------|:------------|
| `./gradlew build` | Build all modules (multiplatform) |
| `./gradlew build -Dkmp.targets=jvm` | JVM only (~5 min) |
| `./gradlew allTests` | Run all tests on configured targets |
| `./gradlew jvmTest` | Run JVM tests only |
| `./gradlew testDebugUnitTest` | Run Android unit tests |
| `./gradlew iosSimulatorArm64Test` | Run iOS simulator tests |
| `./gradlew dokkaGenerate` | Generate API documentation |
| `BUILD_XCFRAMEWORKS=true ./gradlew build` | Build with iOS XCFrameworks |

---

## Related Projects

### [Enterprise Development Kit (EDK)](https://docs.sphereon.com/edk/guides/getting-started)

Sphereon's proprietary product that extends the IDK with the layers required for production enterprise deployments. The IDK provides the identity primitives (cryptography, DIDs, verifiable credentials, SD-JWT, OID4VP, KMS, command/DI framework); the EDK adds:

- **Zero-trust authorization** via the OpenID AuthZEN specification, with Cedarling (Cedar), OPA, and any AuthZEN-compliant PDP supported. Authorization is transparent: a `PolicyCommandExtension` intercepts every command before execution.
- **Identity verification and reconciliation**: composable IDV workflows chaining OIDC, document scanning, biometric, and OTP verification; privacy-preserving identity matching with HMAC-hashed linking; policy-driven reconciliation; an auth bridge from wallet presentations to OAuth2/OIDC.
- **Microservice transport**: dual transport that makes command execution location-transparent. The same command can run in-process or be forwarded to a remote service via HTTP RPC or gRPC, controlled by configuration.
- **Cloud configuration and secrets**: cloud config providers (Azure App Configuration, REST) plus server-issued opaque secret IDs backed by AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault.
- **Audit and compliance**: structured audit logging with sensitive-data redaction, multiple output formats (JSON, CEF, OCSF), tamper evidence via hash chaining and signed checkpoints.

### [Verifiable Data Exchange (VDX)](https://sphereon.com)

The full platform on top of EDK and IDK. An enterprise identity and trust platform that unifies verifiable credentials, digital signatures, wallet-based authentication, and secure data exchange into a single deployable product, with management UIs, workflow orchestration, and operational tooling. Includes the Credential Designer, Issuer/Verifier Management consoles, wallet authentication flow, and white-label branding. Full platform documentation is in progress (Q2 2026).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the upstream-first PR flow and review process.

Open PRs against `develop` on this repo. Maintainers review here, apply the change in the internal repo with a `Co-authored-by:` trailer, and the mirror brings the result back. Your work appears on `develop` with the original attribution.

For security issues, follow the disclosure process in [SECURITY.md](SECURITY.md). Do not open public PRs or issues for vulnerabilities.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built by <a href="https://sphereon.com">Sphereon</a>. Creating Trust In A Digital World.</sub>
</p>

<p align="center">
  <a href="https://sphereon.com">Website</a> &nbsp;&bull;&nbsp;
  <a href="https://docs.sphereon.com/idk/introduction">Documentation</a> &nbsp;&bull;&nbsp;
  <a href="https://github.com/Sphereon-Opensource">GitHub</a>
</p>
