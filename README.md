termseal
========

Erlang term sealing library with legacy TSF v1 support and a newer CMS-based
format built around deterministic canonicalization.

Build
-----

    $ rebar3 compile

What `termseal` does
--------------------

- seals Erlang terms in the legacy TSF v1 format for backward compatibility
- produces explicit canonical-form bytes through `termseal:canonical_form/1,2`
- seals new-format payloads as CMS `SignedData`
- unseals CMS payloads either by direct signer-certificate matching or by
  trust-anchor path validation
- keeps the canonicalization layer separate from the signature container

Canonicalization
----------------

Supported canonicalization identifiers:

- `erlang_etf_minor_v2_legacy`
- `termseal_cbor_erlang_v1`

The authoritative canonicalization specification lives in
`docs/CANONICALIZATION.md`.

`canonical_form/1,2` exists so callers can reason about the exact bytes that
will be signed independently from the seal container format.

Legacy TSF v1 format
--------------------

TSF v1 is the historical format and is still supported unchanged.

`seal(Term)`:

- produces an unsigned TSF v1 box
- encodes `Term` with `term_to_binary(Term, [{minor_version, 2}])`

`seal(Term, Key)` with a bare private key:

- produces a signed TSF v1 box
- uses the same ETF payload bytes as the unsigned form
- signs those bytes directly with SHA-256 using OTP `public_key`

TSF v1 verification:

- `unseal(Box, Certs)` treats `Certs` as direct signer certificates
- verification succeeds when one certificate public key verifies the signature
- TSF v1 does not carry a certificate chain or trust-anchor metadata
- chain validation is therefore not part of the legacy format
- `validate_signer_cert_expiration => true` can be used to reject expired direct
  signer certificates during TSF v1 verification

New CMS format
--------------

Passing a signer-spec map to `seal/2` selects the CMS-based format:

```erlang
termseal:seal(Term, #{
    signer_key => Key,
    signer_cert => SignerCertDer,
    chain => [IntermediateCertDer],
    signature_hash => sha256,
    signature_scheme => rsa_pss
}).
```

Signer-spec defaults and optional fields:

- `signature_hash` is optional and defaults to `sha256`
- `signature_scheme` is optional when `signer_key` is provided
  - with an RSA private key, the default `signature_scheme` is `rsa_pss`
  - with an EC private key, the default `signature_scheme` is `ecdsa`
- `signature_scheme` is required for callback-based signing because `termseal`
  cannot infer it from `signer_fun`
- `chain` is optional; omit it when the signer certificate is directly trusted or
  when no intermediate certificates need to be carried in CMS

The signer-spec map may also use a callback:

```erlang
termseal:seal(Term, #{
    signer_fun => fun(Request) ->
        #{
            signature => Signature,
            signer_cert => SignerCertDer,
            chain => [IntermediateCertDer]
        }
    end,
    signature_hash => sha256,
    signature_scheme => rsa_pss
}).
```

For callback-based signing, the returned `chain` field is optional for the same
reason: only include intermediate certificates that should be embedded in the
CMS object.

How the CMS seal is built
-------------------------

For CMS-based seals, `termseal` uses two layers with different responsibilities.

1. `Term` is canonicalized with the selected canonicalization.
2. The canonical-form bytes are wrapped in a deterministic CBOR envelope.
3. That CBOR envelope becomes the CMS encapsulated content.
4. CMS `SignedData` carries the signer certificate, optional chain, signed
   attributes, and signature.

The CBOR envelope carries:

- `canonicalization_id`
- `payload`

Today:

- the envelope itself is plain deterministic CBOR encoded by `termseal_cbor`
- the default `payload` bytes are Erlang-flavored CBOR encoded by
  `termseal_cbor_erlang`

This design keeps the outer CMS shape stable while allowing future
canonicalization formats to change independently. `unseal/3` first verifies the
CMS object, then decodes the CBOR envelope, then uses `canonicalization_id` to
choose the correct decoder for `payload`.

Signer callbacks
----------------

CMS signer callbacks receive the exact request that must be signed:

- `canonicalization_id`: the selected canonicalization
- `data`: the exact CMS encapsulated content bytes
- `signature_digest`: the digest of `data` using `signature_hash`
- `signature_hash`: `sha256`, `sha384`, or `sha512`
- `signature_scheme`: `rsa_pss`, `rsa_pkcs1_v1_5`, or `ecdsa`

The callback must sign the provided digest according to the provided hash and
scheme. It must not re-canonicalize the term or invent a different digest.

Verification modes
------------------

CMS unsealing supports three verification modes.

`direct_cert`:

- verify the signature against explicitly trusted signer certificates
- no path validation is performed
- signer-certificate expiration is checked only if
  `validate_signer_cert_expiration => true`

`trust_anchor`:

- verify the CMS signature against the embedded signer certificate
- build a chain from the embedded CMS certificates
- validate that chain against configured `trust_anchors`
- certificate expiration is enforced by default
- `disable_expiration_validation => true` disables only the PKIX expiration
  check and is intended for tests or controlled tooling

`both`:

- accept either a successful direct-certificate verification or a successful
  trust-anchor verification

Mode selection rules:

- `unseal(Box, Certs, #{})` uses `direct_cert` when only positional `Certs` are
  provided
- `unseal(Box, [], #{trust_anchors => Anchors})` uses `trust_anchor`
- providing both trusted signer certificates and trust anchors defaults to
  `both`
- positional `Certs` are treated as direct signer certificates, not as trust
  anchors

Security guidance
-----------------

Prefer `trust_anchor` for production CMS verification.

Why:

- it validates the signer certificate through a chain anchored in configured
  trust material
- it rejects missing and wrong chains
- it enforces certificate expiry by default
- it matches the intended update-package trust model better than pinning leaf
  signer certificates everywhere

Use `direct_cert` only when you intentionally want leaf-certificate pinning or
compatibility with workflows that already distribute signer certificates
directly.

Important caveats:

- TSF v1 is a compatibility format; it does not carry chain metadata or a
  canonicalization identifier
- `direct_cert` verification does not imply PKI validation
- `validate_signer_cert_expiration` only checks signer-certificate validity; it
  does not add chain validation
- `disable_expiration_validation` should not be enabled in production flows

Modules
-------

- `src/termseal.erl`: public sealing and unsealing API
- `src/termseal_cbor.erl`: deterministic CBOR codec
- `src/termseal_cbor_erlang.erl`: Erlang-term mapping profile for
  `termseal_cbor_erlang_v1`

Fixtures and tests
------------------

Verification fixtures follow these rules:

- every certificate that is meant to stay valid uses the same long-lived expiry:
  `2099-01-01T00:00:00Z`
- expiry tests use explicitly expired certificates with
  `2024-06-01T00:00:00Z` on only the certificate under test
- all test fixture material is regenerated from `test/generate_test_fixtures.py`
- the CBOR interoperability tests use `python3` plus the optional `cbor2`
  module; if those dependencies are missing, the Python interop test cases are
  skipped rather than failing the whole suite

Ubuntu test dependencies for the Python CBOR interoperability cases:

    $ sudo apt install python3 python3-cbor2

Alternative installation with `pip`:

    $ python3 -m pip install --user cbor2

To run the test suite:

    $ rebar3 ct
