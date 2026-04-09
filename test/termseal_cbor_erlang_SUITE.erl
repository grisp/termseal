%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cbor_erlang_SUITE).
-moduledoc """
Common Test coverage for the Erlang-to-CBOR profile layer.
""".

%=== INCLUDES ==================================================================

-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([encode_atom_uses_tagged_text/1,
         encode_tuple_uses_tagged_array/1,
         encode_large_integer_uses_standard_bignum_tag/1,
         encode_preserves_signed_zero_float/1,
         roundtrip_large_deep_mixed_term/1,
         encode_large_deep_mixed_term_deterministically/1,
         python_decodes_generated_profile/1,
         python_generated_profile_decodes_in_erlang/1,
         roundtrip_nested_term/1,
         map_encoding_is_insertion_order_independent/1,
         reject_improper_lists/1,
         reject_non_byte_aligned_bitstrings/1,
         reject_runtime_terms/1,
         reject_nan/1,
         reject_noncanonical_bignums/1,
         reject_unsupported_map_keys/1,
         reject_unsupported_map_keys_on_decode/1,
         reject_unknown_extension_tag/1,
         reject_plain_cbor_text_reverse_mapping/1,
         reject_unknown_atom_name_in_safe_mode/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [encode_atom_uses_tagged_text,
     encode_tuple_uses_tagged_array,
     encode_large_integer_uses_standard_bignum_tag,
     encode_preserves_signed_zero_float,
     roundtrip_large_deep_mixed_term,
     encode_large_deep_mixed_term_deterministically,
     python_decodes_generated_profile,
     python_generated_profile_decodes_in_erlang,
     roundtrip_nested_term,
     map_encoding_is_insertion_order_independent,
     reject_improper_lists,
     reject_non_byte_aligned_bitstrings,
     reject_runtime_terms,
     reject_nan,
     reject_noncanonical_bignums,
     reject_unsupported_map_keys,
     reject_unsupported_map_keys_on_decode,
     reject_unknown_extension_tag,
     reject_plain_cbor_text_reverse_mapping,
     reject_unknown_atom_name_in_safe_mode].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

encode_atom_uses_tagged_text(_Config) ->
    ?assertEqual(
        {ok, <<16#D9, 16#C3, 16#50, 16#63, $f, $o, $o>>},
        termseal_cbor_erlang:encode(foo)
    ).

encode_tuple_uses_tagged_array(_Config) ->
    ?assertEqual(
        {ok, <<16#D9, 16#C3, 16#51,
               16#82,
               16#D9, 16#C3, 16#50, 16#63, $f, $o, $o,
               1>>},
        termseal_cbor_erlang:encode({foo, 1})
    ).

encode_large_integer_uses_standard_bignum_tag(_Config) ->
    ?assertEqual(
        {ok, <<16#C2, 16#49, 1, 0, 0, 0, 0, 0, 0, 0, 0>>},
        termseal_cbor_erlang:encode(18446744073709551616)
    ).

encode_preserves_signed_zero_float(_Config) ->
    PositiveZero = <<16#FB, 0, 0, 0, 0, 0, 0, 0, 0>>,
    NegativeZero = <<16#FB, 16#80, 0, 0, 0, 0, 0, 0, 0>>,
    ?assertEqual({ok, PositiveZero}, termseal_cbor_erlang:encode(0.0)),
    ?assertEqual({ok, NegativeZero}, termseal_cbor_erlang:encode(-0.0)),
    {ok, PositiveValue} = termseal_cbor_erlang:decode(PositiveZero),
    {ok, NegativeValue} = termseal_cbor_erlang:decode(NegativeZero),
    ?assertEqual({ok, PositiveZero}, termseal_cbor_erlang:encode(PositiveValue)),
    ?assertEqual({ok, NegativeZero}, termseal_cbor_erlang:encode(NegativeValue)).

roundtrip_large_deep_mixed_term(_Config) ->
    Term = large_deep_erlang_term(),
    {ok, Encoded} = termseal_cbor_erlang:encode(Term),
    ?assertEqual({ok, Term}, termseal_cbor_erlang:decode(Encoded)).

encode_large_deep_mixed_term_deterministically(_Config) ->
    TermA = large_deep_erlang_term(),
    TermB = reordered_large_deep_erlang_term(),
    ?assertEqual(termseal_cbor_erlang:encode(TermA), termseal_cbor_erlang:encode(TermB)).

python_decodes_generated_profile(_Config) ->
    with_python_cbor2(
      fun() ->
          Term = python_erlang_term(),
          {ok, Encoded} = termseal_cbor_erlang:encode(Term),
          ?assertEqual({ok, python_erlang_cbor_json()},
                       termseal_python_cbor_interop:decode_to_normalized_json(Encoded))
      end).

python_generated_profile_decodes_in_erlang(_Config) ->
    with_python_cbor2(
      fun() ->
          {ok, Encoded} =
              termseal_python_cbor_interop:encode_from_normalized_json(
                  python_erlang_cbor_json()),
          ?assertEqual({ok, python_erlang_term()},
                       termseal_cbor_erlang:decode(Encoded))
      end).

roundtrip_nested_term(_Config) ->
    Term = {foo, #{bar => [1, 2], 42 => <<"bin">>, <<"blob">> => baz}},
    {ok, Encoded} = termseal_cbor_erlang:encode(Term),
    ?assertEqual({ok, Term}, termseal_cbor_erlang:decode(Encoded)).

map_encoding_is_insertion_order_independent(_Config) ->
    TermA = maps:from_list([{foo, 1}, {42, 2}, {<<"blob">>, 3}]),
    TermB = maps:from_list([{<<"blob">>, 3}, {42, 2}, {foo, 1}]),
    ?assertEqual(termseal_cbor_erlang:encode(TermA), termseal_cbor_erlang:encode(TermB)).

reject_improper_lists(_Config) ->
    ?assertEqual({error, unsupported_term_type}, termseal_cbor_erlang:encode([1 | 2])).

reject_non_byte_aligned_bitstrings(_Config) ->
    ?assertEqual({error, unsupported_term_type},
                 termseal_cbor_erlang:encode(<<1:1>>)).

reject_runtime_terms(_Config) ->
    ?assertEqual({error, unsupported_runtime_term},
                 termseal_cbor_erlang:encode(make_ref())),
    ?assertEqual({error, unsupported_runtime_term},
                 termseal_cbor_erlang:encode(self())),
    ?assertEqual({error, unsupported_runtime_term},
                 termseal_cbor_erlang:encode(fun erlang:self/0)).

reject_nan(_Config) ->
    ?assertEqual({error, non_canonical_nan},
                 termseal_cbor_erlang:decode(
                     <<16#FB, 16#7F, 16#F8, 0, 0, 0, 0, 0, 0>>
                 )).

reject_noncanonical_bignums(_Config) ->
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor_erlang:decode(<<16#C2, 16#41, 1>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor_erlang:decode(<<16#C3, 16#41, 1>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor_erlang:decode(<<16#C2, 16#40>>)),
    ?assertEqual({error, non_canonical_cbor},
                 termseal_cbor_erlang:decode(<<16#C2, 16#42, 0, 1>>)).

reject_unsupported_map_keys(_Config) ->
    ?assertEqual({error, unsupported_map_key}, termseal_cbor_erlang:encode(#{{foo} => bar})).

reject_unsupported_map_keys_on_decode(_Config) ->
    ?assertEqual({error, unsupported_map_key},
                 termseal_cbor_erlang:decode(
                     <<16#A1, 16#FB, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
                 )).

reject_unknown_extension_tag(_Config) ->
    ?assertEqual({error, unknown_extension_tag},
                 termseal_cbor_erlang:decode(<<16#D9, 16#03, 16#E7, 0>>)).

reject_plain_cbor_text_reverse_mapping(_Config) ->
    ?assertEqual({error, unsupported_reverse_mapping}, termseal_cbor_erlang:decode(<<16#63, $f, $o, $o>>)).

reject_unknown_atom_name_in_safe_mode(_Config) ->
    ?assertEqual(
        {error, unknown_atom_name},
        termseal_cbor_erlang:decode(<<16#D9, 16#C3, 16#50, 16#78, 30,
                                      "termseal_nonexistent_atom_name">>)
    ).


%=== INTERNAL FUNCTIONS ========================================================

with_python_cbor2(Fun) ->
    case termseal_python_cbor_interop:ensure_available() of
        ok ->
            Fun();
        {skip, Reason} ->
            {skip, Reason}
    end.

python_erlang_term() ->
    {foo, #{bar => [1, 2], 42 => <<"bin">>, <<"blob">> => baz}}.

python_erlang_cbor_json() ->
    <<"{\"tag\":50001,\"value\":{\"array\":[{\"tag\":50000,\"value\":{\"text\":\"foo\"}},{\"map\":[[42,{\"bytes\":\"62696e\"}],[{\"bytes\":\"626c6f62\"},{\"tag\":50000,\"value\":{\"text\":\"baz\"}}],[{\"tag\":50000,\"value\":{\"text\":\"bar\"}},{\"array\":[1,2]}]]}]}}">>.

large_deep_erlang_term() ->
    deep_erlang_term(10).

reordered_large_deep_erlang_term() ->
    deep_erlang_term_reordered(10).

deep_erlang_term(0) ->
    {leaf,
     #{alpha => [foo, 0, -1, 1.25, 18446744073709551616, -18446744073709551617],
       7 => {tuple_leaf, <<"bin">>, [bar, baz]},
       <<"bytes-key">> => #{beta => <<"done">>, 8 => []}}};
deep_erlang_term(Level) ->
    Child = deep_erlang_term(Level - 1),
    {level,
     Level,
     #{alpha => [foo,
                 Level,
                 -Level,
                 Level / 2,
                 {mix, <<Level, (Level + 1), (Level + 2)>>, [bar, {baz, Level + 10}]},
                 Child],
       Level => {branch,
                 <<Level, (Level + 1)>>,
                 [18446744073709551616 + Level, -18446744073709551617 - Level]},
       <<"bytes-key">> => #{beta => {leaf, Level + 1000},
                            0 => [<<"bin">>, zig, {zag, Level * Level}],
                            <<"nested">> => {marker, Level, <<"single-recursive-edge">>}}}}.

deep_erlang_term_reordered(0) ->
    {leaf,
     maps:from_list([{<<"bytes-key">>, maps:from_list([{8, []}, {beta, <<"done">>}])},
                     {7, {tuple_leaf, <<"bin">>, [bar, baz]}},
                     {alpha, [foo, 0, -1, 1.25, 18446744073709551616, -18446744073709551617]}])};
deep_erlang_term_reordered(Level) ->
    Child = deep_erlang_term_reordered(Level - 1),
    {level,
     Level,
     maps:from_list([{<<"bytes-key">>,
                      maps:from_list([{<<"nested">>, {marker, Level, <<"single-recursive-edge">>}},
                                      {0, [<<"bin">>, zig, {zag, Level * Level}]},
                                      {beta, {leaf, Level + 1000}}])},
                     {Level,
                      {branch,
                       <<Level, (Level + 1)>>,
                       [18446744073709551616 + Level, -18446744073709551617 - Level]}},
                     {alpha,
                      [foo,
                       Level,
                       -Level,
                       Level / 2,
                       {mix, <<Level, (Level + 1), (Level + 2)>>, [bar, {baz, Level + 10}]},
                       Child]}])}.
