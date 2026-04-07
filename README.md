termseal
========

Erlang Term Sealing library

Build
-----

    $ rebar3 compile

Current capabilities
--------------------

- TSF v1 sealing and unsealing based on the legacy ETF payload rule.
- Deterministic CBOR canonical-form generation for new signing flows via `termseal:canonical_form/1,2`.
- CMS signer callbacks receive the exact wrapped bytes to sign plus the precomputed digest, selected hash, and selected signature scheme.
- CMS unsealing supports direct trusted signer certificates or trust-anchor validation for CMS `SignedData`.
- Direct trusted-certificate verification in TSF v1 and CMS accepts `validate_signer_cert_expiration => true` to reject expired signer certificates.
- CMS unsealing accepts `disable_expiration_validation => true` when tests or controlled tooling need to ignore certificate expiry.
- Standalone deterministic CBOR and Erlang/CBOR profile modules in:
  - `src/termseal_cbor.erl`
  - `src/termseal_cbor_erlang.erl`

Canonicalization
----------------

- Legacy TSF v1 canonicalization identifier: `erlang_etf_minor_v2_legacy`
- Stable CBOR-based canonicalization identifier: `termseal_cbor_erlang_v1`

The authoritative canonicalization spec lives in `docs/CANONICALIZATION.md`.

CMS content model
-----------------

For CMS-based seals, `termseal` uses two layers with different roles:

- The outer CMS `eContent` is a stable `termseal` envelope encoded as ordinary deterministic CBOR.
- The inner `payload` field of that envelope contains the canonical-form bytes for the selected canonicalization.

Today that means:

- the envelope is plain CBOR understood by `termseal_cbor`
- the default canonical-form bytes inside the envelope are Erlang-flavored CBOR produced by `termseal_cbor_erlang`

The signed CBOR envelope carries:

- `canonicalization_id`
- `payload`

The `canonicalization_id` tells `unseal` which decoder to use for the embedded canonical-form bytes after the CMS content has been verified and the CBOR envelope has been decoded.

This separation is intentional:

- the CMS envelope format can stay stable across future canonicalization versions
- future canonicalizations do not need to be CBOR-based, because the envelope stores their output as raw bytes
- only the decoder selected by `canonicalization_id` needs to change when a new canonicalization is introduced

CMS verification fixtures
-------------------------

The verification fixtures follow these rules:

- every certificate that is meant to stay valid uses the same long-lived expiry: `2099-01-01T00:00:00Z`
- expiry tests use explicitly expired certificates with `2024-06-01T00:00:00Z` on only the certificate under test
- all test fixture material is regenerated from `test/generate_test_fixtures.py`
