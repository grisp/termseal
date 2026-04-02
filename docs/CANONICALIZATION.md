# Canonicalization Format

This document is the normative definition of the `termseal_cbor_erlang_v1` canonicalization used by `termseal`.

For every supported Erlang term, there is exactly one valid canonical byte sequence and exactly one accepted reverse mapping. Any alternative encoding of the same logical value is non-canonical and must be rejected.

This document defines only the canonicalization format itself. It does not define signing APIs, transport formats, workflow, or project planning.

`termseal` also has a legacy payload rule based on `term_to_binary(Term, [{minor_version, 2}])` for TSF v1 compatibility. That legacy rule is not specified by this document and is not part of `termseal_cbor_erlang_v1`.

## Goals

- Stable across supported Erlang/OTP versions.
- Deterministic and straightforward to review.
- Decodable in other languages with an ordinary CBOR implementation plus a small `termseal` profile.
- Precise enough that independent encoders and decoders produce identical bytes.

## Non-Goals

- Reproducing the exact bytes of Erlang external term format.
- Supporting every Erlang term kind.
- Encoding runtime-bound terms whose identity is tied to a live VM instance.
- Making all Erlang terms feel native in non-Erlang languages.

## Canonicalization Identifier

- `termseal_cbor_erlang_v1`

If an implementation claims to emit or accept `termseal_cbor_erlang_v1`, it must follow this document exactly.

## Supported Erlang Terms

`termseal_cbor_erlang_v1` supports the following Erlang term categories:

- atoms
- integers
- floats
- binaries
- tuples
- proper lists
- maps with a restricted key subset

Derived language constructs are represented through their underlying Erlang term representation:

- records as tuples
- strings as proper lists of integers

## Rejected Erlang Terms

The following terms must be rejected by `termseal_cbor_erlang_v1`:

- non-byte-aligned bitstrings
- improper lists
- references
- functions and funs, including external funs
- pids
- ports

Canonicalization must fail explicitly for unsupported terms.

## CBOR Basis

The canonicalized payload is deterministic CBOR with a small Erlang-specific profile layered on top.

Normative conventions used below:

- deterministic encoding uses definite lengths only
- integers and length headers must use preferred CBOR shortest-form encoding
- map keys are ordered using the deterministic ordering of their encoded CBOR bytes: shorter key encodings sort first; equal-length encodings sort lexicographically by raw bytes
- floats are always encoded as IEEE-754 binary64, even when a shorter CBOR float width could represent the same numeric value
- all rules using `must`, `must not`, `required`, or `rejected` are normative

This profile is based on the deterministic CBOR rules from [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949), with the fixed Erlang-specific rules defined below.

## Extension Tags

The profile uses two Erlang-specific CBOR tags in the application-specific range:

- tag `50000`: Erlang atom
- tag `50001`: Erlang tuple

These tags are part of the `termseal_cbor_erlang_v1` profile.

The profile also uses the standard CBOR bignum tags when an Erlang integer is outside CBOR's native 64-bit integer range:

- tag `2`: standard positive bignum
- tag `3`: standard negative bignum

## Forward Mapping: Erlang To Canonical CBOR

### Atoms

Erlang atoms are encoded as:

- CBOR tag `50000`
- tagged content: CBOR text string containing `atom_to_binary(Atom, utf8)`

Rules:

- atoms are encoded by name, not by VM atom table position
- `true`, `false`, `undefined`, and all other atoms use the same tagged encoding
- plain CBOR booleans must not be used for Erlang atoms in this profile

Example shape:

- `foo` -> `50000("foo")`

### Integers

Erlang integers are encoded as either native CBOR integers or standard CBOR bignums.

Rules:

- non-negative integers use major type `0`
- negative integers use major type `1`
- the encoder must use the preferred shortest-form integer encoding
- zero has exactly one encoding: CBOR unsigned integer zero
- integers in the inclusive range `0 .. 18446744073709551615` use native CBOR unsigned integers
- integers in the inclusive range `-18446744073709551616 .. -1` use native CBOR negative integers
- integers greater than `18446744073709551615` use tag `2` around a byte string containing the unsigned big-endian magnitude with no leading zero bytes
- integers less than `-18446744073709551616` use tag `3` around a byte string containing the unsigned big-endian magnitude of `(-1 - Integer)` with no leading zero bytes

### Floats

Erlang floats are encoded as native CBOR floating-point numbers with binary64 width.

Rules:

- floats must always use the 64-bit CBOR float form
- `+0.0` and `-0.0` remain distinct
- positive and negative infinity are allowed
- any NaN value must be rejected with `non_canonical_nan`

### Binaries

Erlang binaries are encoded as native CBOR byte strings.

Rules:

- the encoder must use a definite-length byte string
- non-byte-aligned bitstrings are rejected and are not normalized

### Tuples

Erlang tuples are encoded as:

- CBOR tag `50001`
- tagged content: CBOR array of each tuple element in order

Rules:

- tuple element order is preserved exactly
- the tagged content must be an array, not any other CBOR type

Example shape:

- `{a, 1}` -> `50001([50000("a"), 1])`

### Proper Lists

Erlang proper lists are encoded as native CBOR arrays.

Rules:

- list element order is preserved exactly
- strings are not given special treatment beyond list encoding
- improper lists are rejected

### Maps

Erlang maps are encoded as native CBOR maps.

Allowed Erlang map key types:

- atoms
- integers
- binaries

Rejected as map keys:

- floats
- tuples
- lists
- maps
- unsupported runtime-bound terms

Rules:

- each allowed map key is encoded using the same rules it would use as a standalone term
- map entry order must be determined only by deterministic CBOR ordering of the encoded keys
- if two distinct Erlang keys encode to identical canonical CBOR key bytes, canonicalization must fail with `duplicate_canonical_map_key`
- values may be any supported non-key term category

## Reverse Mapping: Canonical CBOR To Erlang

A `termseal_cbor_erlang_v1` decoder must accept only the canonical CBOR forms described below. It must reject semantically equivalent but non-canonical alternatives.

### CBOR Integers

- CBOR unsigned or negative integers map to Erlang integers
- CBOR tag `2` positive bignums map to Erlang integers greater than `18446744073709551615`
- CBOR tag `3` negative bignums map to Erlang integers less than `-18446744073709551616`
- non-preferred integer encodings must be rejected
- tag `2` or `3` must be rejected when the value could have been encoded as a native CBOR integer

### CBOR Binary64 Floats

- CBOR binary64 floats map to Erlang floats
- non-binary64 float encodings must be rejected
- NaN values must be rejected

### CBOR Byte Strings

- definite-length CBOR byte strings map to Erlang binaries

### CBOR Arrays

- plain CBOR arrays map to Erlang proper lists
- array length and element order are preserved exactly

### CBOR Maps

When decoding a CBOR map in this profile:

- each key must decode to one of the allowed Erlang key types for `v1`
- duplicate keys after Erlang reconstruction must be rejected
- map order in the encoded CBOR is not preserved as Erlang map iteration order and has no semantic meaning beyond canonicalization

### Tag `50000`: Erlang Atom

Tag `50000` maps to an Erlang atom only when:

- the tagged item is a CBOR text string
- the text string is valid UTF-8
- the atom name is accepted by the decoder's atom policy

Atom decoding policy:

- decode using `binary_to_existing_atom(Name, utf8)`
- reject unknown atom names with `unknown_atom_name`

### Tag `50001`: Erlang Tuple

Tag `50001` maps to an Erlang tuple only when:

- the tagged item is a CBOR array
- every element of that array is itself a valid `termseal_cbor_erlang_v1` term

The resulting Erlang tuple preserves the array element order exactly.

## Unsupported Reverse Mappings

The following CBOR items must be rejected by a `termseal_cbor_erlang_v1` decoder:

- CBOR booleans
- CBOR null or undefined simple values
- CBOR text strings that are not wrapped by a recognized Erlang-extension tag
- CBOR tags other than the tags defined by this profile
- indefinite-length CBOR items
- non-canonical integer, float, string, array, or map encodings

This profile is intentionally narrow. A generic CBOR decoder may understand more CBOR than a `termseal_cbor_erlang_v1` decoder is allowed to accept.

## Bidirectional Mapping Summary

| Erlang term | Canonical CBOR form | Reverse mapping |
| --- | --- | --- |
| atom | tag `50000` around text string | tag `50000` + text -> atom |
| integer | native CBOR integer or standard bignum tag | integer or standard bignum tag -> integer |
| float | native CBOR binary64 float | binary64 float -> float |
| binary | native CBOR byte string | byte string -> binary |
| tuple | tag `50001` around array | tag `50001` + array -> tuple |
| proper list | native CBOR array | plain array -> proper list |
| map | native CBOR map | plain map -> map |

## Deterministic Map Ordering

Map ordering is inherited from deterministic CBOR ordering of the encoded key bytes.

For `termseal_cbor_erlang_v1` this means:

1. Encode each key into its canonical standalone CBOR byte sequence.
2. Sort keys by encoded length, shortest first.
3. If two key encodings have the same length, sort lexicographically by raw bytes.
4. Emit each key followed by its canonicalized value.

No Erlang VM map iteration behavior may influence the output bytes.

## Error Semantics

Canonicalization and decoding must return typed errors for unsupported or invalid data.

Error categories:

- `unsupported_term_type`
- `unsupported_runtime_term`
- `unsupported_map_key`
- `non_canonical_nan`
- `duplicate_canonical_map_key`
- `invalid_cbor`
- `non_canonical_cbor`
- `unknown_extension_tag`
- `invalid_extension_tag_content`
- `unknown_atom_name`

The exact error tuple shape is implementation-defined, but implementations must distinguish canonicalization failure from unrelated failures.

## Resolved v1 Choices

The following decisions are fixed for `termseal_cbor_erlang_v1` and are not left to implementation choice:

- deterministic CBOR is the underlying wire format
- Erlang atoms and tuples use explicit extension tags
- binaries use native CBOR byte strings
- proper lists use native CBOR arrays
- maps are restricted to atom, integer, and binary keys
- improper lists and non-byte-aligned bitstrings are rejected
- floats are always encoded as CBOR binary64
- unknown atom names are rejected
