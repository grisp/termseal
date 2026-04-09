# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add a CommonTest TSF v1 regression baseline with frozen compatibility fixtures for signed and unsigned seals, malformed-input handling, and key-loading edge cases.
- Add `termseal_cbor` as a standalone deterministic CBOR codec and `termseal_cbor_erlang` as the Erlang-term mapping profile for canonical signing payloads.
- Add `canonical_form/1,2` for explicit canonical-form generation independent from legacy TSF v1 sealing.
- Add focused Common Test coverage for canonical CBOR float rules, malformed-CBOR rejection, non-canonical bignums, unsupported Erlang runtime terms, and decode-side map-key restrictions.
- Add a CMS sealing contract suite with dedicated CMS root/intermediate/leaf fixture material that captures the expected `SignedData` container shape, embedded signer certificate and chain handling, encapsulated signed-content wrapping, and callback canonicalization metadata behavior for the upcoming CMS path.
- Add a CMS verification contract suite with frozen CMS `SignedData` fixtures covering trust-anchor success, missing and wrong chains, and expired root/intermediate/leaf certificate cases.
- Add `disable_expiration_validation` for CMS unsealing so controlled tests can bypass certificate expiry checks when needed.
- Add a reproducible test fixture generator at `test/generate_test_fixtures.py` for CMS verification, CMS sealing, and TSF v1 certificate material.
- Add test coverage for opt-in signer-certificate expiration validation in both legacy TSF v1 direct verification and CMS direct-cert verification.
- Add tamper-path verification coverage for TSF v1 payload mutation and CMS signature and payload mutation.
- Add optional Python `cbor2` interoperability coverage for `termseal_cbor` and `termseal_cbor_erlang`.

### Changed

- Configure Dialyzer to include the OTP applications needed for `public_key`-based analysis.
- Replace the earlier custom canonical byte-format draft with the normative `termseal_cbor_erlang_v1` deterministic-CBOR profile, including Erlang extension tags for atoms and tuples and explicit rejection of improper lists and non-byte-aligned bitstrings.
- Tighten deterministic CBOR decoding to reject invalid UTF-8 text and NaN float encodings with the documented canonicalization errors.
- Extend `termseal:seal/2` so map-based signer specs now produce CMS `SignedData` with deterministic wrapped signed content, embedded signer certificate and chain material, callback requests shaped around the exact bytes and digest to sign, and explicit `rsa_pkcs1_v1_5`, `rsa_pss`, and `ecdsa` scheme handling while bare-key calls remain TSF v1.
- Use OTP `pkix_path_validation/3` for CMS trust-anchor verification with the correct certificate-chain ordering, and normalize all non-expired verification fixtures to the same long-lived `2099-01-01` expiry.
- Add `validate_signer_cert_expiration` as an opt-in for direct trusted-certificate verification in both TSF v1 unsealing and CMS direct-cert unsealing.
- Document the optional Ubuntu and `pip` installation paths for the Python CBOR interoperability test dependency and make the interop tests skip cleanly when `cbor2` is unavailable.

## [0.1.1] - 2024-09-05

### Fixed

- Load properly generic private key PEM entries 'PrivateKeyInfo'.

## [0.1.0] - 2024-09-02

First release


[Unreleased]: https://github.com/grisp/termseal/compare/0.1.1...HEAD
[0.1.1]: https://github.com/grisp/termseal/compare/0.1.0...0.1.1
[0.1.0]: https://github.com/grisp/termseal/compare/4f87e9fffb7ac19be8f588c44e60ea1a9cf71c77...0.1.0
