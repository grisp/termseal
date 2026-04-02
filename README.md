termseal
========

Erlang Term Sealing library

Build
-----

    $ rebar3 compile

Current capabilities
--------------------

- TSF v1 sealing and unsealing based on the legacy ETF payload rule.
- Deterministic CBOR canonical payload generation for new signing flows via `termseal:signing_payload/1,2`.
- Normalized signing-request generation via `termseal:signing_request/1,2`.
- Standalone deterministic CBOR and Erlang/CBOR profile modules in:
  - `src/termseal_cbor.erl`
  - `src/termseal_cbor_erlang.erl`

Canonicalization
----------------

- Legacy TSF v1 payload identifier: `erlang_etf_minor_v2_legacy`
- Stable CBOR-based payload identifier: `termseal_cbor_erlang_v1`

The authoritative canonicalization spec lives in `docs/CANONICALIZATION.md`.
