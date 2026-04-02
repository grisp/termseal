%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_signing_payload_SUITE).
-moduledoc """
Common Test coverage for canonical payload helpers in `termseal`.
""".

%=== INCLUDES ==================================================================

-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([default_signing_payload_uses_cbor_profile/1,
         legacy_signing_payload_matches_term_to_binary/1,
         signing_request_contains_payload_digests/1,
         unknown_canonicalization_is_rejected/1,
         legacy_seal_roundtrip_remains_unchanged/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [default_signing_payload_uses_cbor_profile,
     legacy_signing_payload_matches_term_to_binary,
     signing_request_contains_payload_digests,
     unknown_canonicalization_is_rejected,
     legacy_seal_roundtrip_remains_unchanged].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

default_signing_payload_uses_cbor_profile(_Config) ->
    Term = {foo, #{bar => [1, 2], 42 => <<"bin">>}},
    {ok, Expected} = termseal_cbor_erlang:encode(Term),
    ?assertEqual(Expected, termseal:signing_payload(Term)),
    ?assertEqual(termseal_cbor_erlang_v1, termseal:canonicalization_id()).

legacy_signing_payload_matches_term_to_binary(_Config) ->
    Term = {foo, 42},
    ?assertEqual(
        term_to_binary(Term, [{minor_version, 2}]),
        termseal:signing_payload(Term, erlang_etf_minor_v2_legacy)
    ).

signing_request_contains_payload_digests(_Config) ->
    Term = {foo, <<"bar">>},
    Payload = termseal:signing_payload(Term),
    Digest = crypto:hash(sha256, Payload),
    ?assertEqual(
        #{
            canonicalization_id => termseal_cbor_erlang_v1,
            payload => Payload,
            payload_digest => Digest,
            signing_digest => Digest,
            signing_subject => payload,
            signature_hash => sha256,
            signature_scheme => direct_signature
        },
        termseal:signing_request(Term)
    ).

unknown_canonicalization_is_rejected(_Config) ->
    ?assertThrow(
        {unsupported_canonicalization_id, unknown_format},
        termseal:signing_payload(foo, unknown_format)
    ).

legacy_seal_roundtrip_remains_unchanged(_Config) ->
    Term = {foo, #{bar => 1}},
    Box = termseal:seal(Term),
    ?assertEqual({unsigned, Term}, termseal:unseal(Box, [], #{allow_unsigned => true})).
