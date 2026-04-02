%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cbor_SUITE).
-moduledoc """
Common Test coverage for the deterministic CBOR codec.
""".

%=== INCLUDES ==================================================================

-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([encode_preferred_integers/1,
         encode_sorts_map_keys_deterministically/1,
         encode_binary64_floats/1,
         roundtrip_tagged_values/1,
         roundtrip_signed_zero_float/1,
         reject_noncanonical_integer_width/1,
         reject_nan_float/1,
         reject_non_binary64_floats/1,
         reject_unsorted_map_keys/1,
         reject_duplicate_map_keys/1,
         reject_indefinite_length_items/1,
         reject_invalid_utf8_text/1,
         reject_simple_values_outside_profile/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [encode_preferred_integers,
     encode_sorts_map_keys_deterministically,
     encode_binary64_floats,
     roundtrip_tagged_values,
     roundtrip_signed_zero_float,
     reject_noncanonical_integer_width,
     reject_nan_float,
     reject_non_binary64_floats,
     reject_unsorted_map_keys,
     reject_duplicate_map_keys,
     reject_indefinite_length_items,
     reject_invalid_utf8_text,
     reject_simple_values_outside_profile].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

encode_preferred_integers(_Config) ->
    ?assertEqual({ok, <<0>>}, termseal_cbor:encode(0)),
    ?assertEqual({ok, <<16#17>>}, termseal_cbor:encode(23)),
    ?assertEqual({ok, <<16#18, 16#18>>}, termseal_cbor:encode(24)),
    ?assertEqual({ok, <<16#19, 16#01, 16#00>>}, termseal_cbor:encode(256)),
    ?assertEqual({ok, <<16#20>>}, termseal_cbor:encode(-1)),
    ?assertEqual({ok, <<16#38, 16#18>>}, termseal_cbor:encode(-25)).

encode_sorts_map_keys_deterministically(_Config) ->
    Value = {map, [{{bytes, <<"aa">>}, 2},
                   {{bytes, <<"b">>}, 3},
                   {{bytes, <<"a">>}, 1}]},
    ?assertEqual(
        {ok, <<16#A3,
               16#41, $a, 1,
               16#41, $b, 3,
               16#42, $a, $a, 2>>},
        termseal_cbor:encode(Value)
    ).

encode_binary64_floats(_Config) ->
    ?assertEqual({ok, <<16#FB, 16#3F, 16#F8, 0, 0, 0, 0, 0, 0>>},
                 termseal_cbor:encode(1.5)).

roundtrip_tagged_values(_Config) ->
    Value = {tag, 50001, {array, [1, -2, {bytes, <<1, 2>>}, {text, <<"ok">>}]}},
    {ok, Encoded} = termseal_cbor:encode(Value),
    ?assertEqual({ok, Value}, termseal_cbor:decode(Encoded)).

roundtrip_signed_zero_float(_Config) ->
    PositiveZero = <<16#FB, 0, 0, 0, 0, 0, 0, 0, 0>>,
    NegativeZero = <<16#FB, 16#80, 0, 0, 0, 0, 0, 0, 0>>,
    {ok, PositiveValue} = termseal_cbor:decode(PositiveZero),
    {ok, NegativeValue} = termseal_cbor:decode(NegativeZero),
    ?assertEqual({ok, PositiveZero}, termseal_cbor:encode(PositiveValue)),
    ?assertEqual({ok, NegativeZero}, termseal_cbor:encode(NegativeValue)).

reject_noncanonical_integer_width(_Config) ->
    ?assertEqual({error, non_canonical_cbor}, termseal_cbor:decode(<<16#18, 16#17>>)).

reject_nan_float(_Config) ->
    ?assertEqual({error, non_canonical_nan},
                 termseal_cbor:decode(<<16#FB, 16#7F, 16#F8, 0, 0, 0, 0, 0, 0>>)).

reject_non_binary64_floats(_Config) ->
    ?assertEqual({error, non_canonical_cbor}, termseal_cbor:decode(<<16#F9, 16#3C, 0>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor:decode(<<16#FA, 16#3F, 16#80, 0, 0>>)).

reject_unsorted_map_keys(_Config) ->
    ?assertEqual(
        {error, non_canonical_cbor},
        termseal_cbor:decode(<<16#A2,
                               16#41, $b, 1,
                               16#41, $a, 2>>)
    ).

reject_duplicate_map_keys(_Config) ->
    ?assertEqual(
        {error, duplicate_canonical_map_key},
        termseal_cbor:decode(<<16#A2,
                               16#41, $a, 1,
                               16#41, $a, 2>>)
    ).

reject_indefinite_length_items(_Config) ->
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor:decode(<<16#5F, 16#40, 16#FF>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor:decode(<<16#7F, 16#60, 16#FF>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor:decode(<<16#9F, 1, 16#FF>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor:decode(<<16#BF, 1, 2, 16#FF>>)).

reject_invalid_utf8_text(_Config) ->
    ?assertEqual({error, invalid_utf8}, termseal_cbor:decode(<<16#61, 16#80>>)).

reject_simple_values_outside_profile(_Config) ->
    ?assertEqual({error, non_canonical_cbor}, termseal_cbor:decode(<<16#F5>>)).
