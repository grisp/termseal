%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_canonical_form_SUITE).
-moduledoc """
Common Test coverage for canonical form helpers in `termseal`.
""".

%=== INCLUDES ==================================================================

-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([default_canonical_form_uses_cbor_profile/1,
         legacy_canonical_form_matches_term_to_binary/1,
         unknown_canonicalization_is_rejected/1,
         legacy_seal_roundtrip_remains_unchanged/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [default_canonical_form_uses_cbor_profile,
     legacy_canonical_form_matches_term_to_binary,
     unknown_canonicalization_is_rejected,
     legacy_seal_roundtrip_remains_unchanged].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

default_canonical_form_uses_cbor_profile(_Config) ->
    Term = {foo, #{bar => [1, 2], 42 => <<"bin">>}},
    {ok, Expected} = termseal_cbor_erlang:encode(Term),
    ?assertEqual(Expected, termseal:canonical_form(Term)).

legacy_canonical_form_matches_term_to_binary(_Config) ->
    Term = {foo, 42},
    ?assertEqual(
        term_to_binary(Term, [{minor_version, 2}]),
        termseal:canonical_form(Term, erlang_etf_minor_v2_legacy)
    ).

unknown_canonicalization_is_rejected(_Config) ->
    ?assertThrow(
        {unsupported_canonicalization_id, unknown_format},
        termseal:canonical_form(foo, unknown_format)
    ).

legacy_seal_roundtrip_remains_unchanged(_Config) ->
    Term = {foo, #{bar => 1}},
    Box = termseal:seal(Term),
    ?assertEqual({unsigned, Term}, termseal:unseal(Box, [], #{allow_unsigned => true})).
