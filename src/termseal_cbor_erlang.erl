%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cbor_erlang).
-moduledoc """
Map Erlang terms to and from the `termseal_cbor_erlang_v1` profile.

This module applies the profile rules from `docs/CANONICALIZATION.md` on top of
the raw deterministic CBOR codec.
""".

%=== EXPORTS ===================================================================

-export([canonicalization_id/0]).
-export([encode/1]).
-export([decode/1]).


%=== MACROS ====================================================================

-define(ATOM_TAG, 50000).
-define(TUPLE_TAG, 50001).
-define(UINT64_MAX, 16#FFFFFFFFFFFFFFFF).


%=== API FUNCTIONS =============================================================

-doc "Return the canonicalization identifier implemented by this module.".
-spec canonicalization_id() -> termseal_cbor_erlang_v1.
canonicalization_id() ->
    termseal_cbor_erlang_v1.

-doc "Encode an Erlang term using the `termseal_cbor_erlang_v1` profile.".
-spec encode(term()) -> {ok, binary()} | {error, term()}.
encode(Term) ->
    try
        termseal_cbor:encode(term_to_cbor(Term))
    catch
        throw:Reason -> {error, Reason}
    end.

-doc "Decode canonical `termseal_cbor_erlang_v1` bytes into an Erlang term.".
-spec decode(binary()) -> {ok, term()} | {error, term()}.
decode(Bin) ->
    case termseal_cbor:decode(Bin) of
        {ok, Value} ->
            try
                {ok, cbor_to_term(Value)}
            catch
                throw:Reason -> {error, Reason}
            end;
        Error ->
            Error
    end.


%=== INTERNAL FUNCTIONS ========================================================

term_to_cbor(Term) when is_atom(Term) ->
    {tag, ?ATOM_TAG, {text, atom_to_binary(Term, utf8)}};
term_to_cbor(Term) when is_integer(Term) ->
    integer_to_cbor(Term);
term_to_cbor(Term) when is_float(Term) ->
    ensure_not_nan(Term),
    Term;
term_to_cbor(Term) when is_binary(Term) ->
    {bytes, Term};
term_to_cbor(Term) when is_bitstring(Term) ->
    throw(unsupported_term_type);
term_to_cbor(Term) when is_tuple(Term) ->
    {tag, ?TUPLE_TAG, {array, [term_to_cbor(Element) || Element <- tuple_to_list(Term)]}};
term_to_cbor(Term) when is_list(Term) ->
    {array, encode_proper_list(Term)};
term_to_cbor(Term) when is_map(Term) ->
    {map, encode_map_pairs(maps:to_list(Term))};
term_to_cbor(Term) when is_reference(Term); is_pid(Term); is_port(Term); is_function(Term) ->
    throw(unsupported_runtime_term);
term_to_cbor(_Term) ->
    throw(unsupported_term_type).

integer_to_cbor(Term) when Term >= 0, Term =< ?UINT64_MAX ->
    Term;
integer_to_cbor(Term) when Term < 0, Term >= -1 - ?UINT64_MAX ->
    Term;
integer_to_cbor(Term) when Term > ?UINT64_MAX ->
    {tag, 2, {bytes, minimal_unsigned_bytes(Term)}};
integer_to_cbor(Term) ->
    {tag, 3, {bytes, minimal_unsigned_bytes(-1 - Term)}}.

encode_proper_list([]) ->
    [];
encode_proper_list([Head | Tail]) ->
    [term_to_cbor(Head) | encode_proper_list(Tail)];
encode_proper_list(_ImproperTail) ->
    throw(unsupported_term_type).

encode_map_pairs(Pairs) ->
    [{map_key_to_cbor(Key), term_to_cbor(Value)} || {Key, Value} <- Pairs].

map_key_to_cbor(Key) when is_atom(Key) ->
    term_to_cbor(Key);
map_key_to_cbor(Key) when is_integer(Key) ->
    integer_to_cbor(Key);
map_key_to_cbor(Key) when is_binary(Key) ->
    {bytes, Key};
map_key_to_cbor(_Key) ->
    throw(unsupported_map_key).

cbor_to_term({tag, ?ATOM_TAG, {text, Name}}) ->
    decode_existing_atom(Name);
cbor_to_term({tag, ?TUPLE_TAG, {array, Elements}}) ->
    list_to_tuple([cbor_to_term(Element) || Element <- Elements]);
cbor_to_term({tag, ?ATOM_TAG, _Other}) ->
    throw(invalid_extension_tag_content);
cbor_to_term({tag, ?TUPLE_TAG, _Other}) ->
    throw(invalid_extension_tag_content);
cbor_to_term({tag, 2, {bytes, MagnitudeBytes}}) ->
    positive_bignum_to_integer(MagnitudeBytes);
cbor_to_term({tag, 3, {bytes, MagnitudeBytes}}) ->
    negative_bignum_to_integer(MagnitudeBytes);
cbor_to_term({tag, 2, _Other}) ->
    throw(invalid_extension_tag_content);
cbor_to_term({tag, 3, _Other}) ->
    throw(invalid_extension_tag_content);
cbor_to_term({tag, _Tag, _Value}) ->
    throw(unknown_extension_tag);
cbor_to_term({bytes, Bytes}) ->
    Bytes;
cbor_to_term({text, _Text}) ->
    throw(unsupported_reverse_mapping);
cbor_to_term({array, Values}) ->
    [cbor_to_term(Value) || Value <- Values];
cbor_to_term({map, Pairs}) ->
    decode_map_pairs(Pairs, #{});
cbor_to_term(Value) when is_integer(Value) ->
    Value;
cbor_to_term(Value) when is_float(Value) ->
    ensure_not_nan(Value),
    Value.

decode_map_pairs([], Acc) ->
    Acc;
decode_map_pairs([{KeyValue, ValueValue} | Rest], Acc) ->
    Key = cbor_key_to_term(KeyValue),
    case maps:is_key(Key, Acc) of
        true ->
            throw(duplicate_canonical_map_key);
        false ->
            decode_map_pairs(Rest, maps:put(Key, cbor_to_term(ValueValue), Acc))
    end.

cbor_key_to_term({tag, ?ATOM_TAG, {text, Name}}) ->
    decode_existing_atom(Name);
cbor_key_to_term({tag, 2, {bytes, MagnitudeBytes}}) ->
    positive_bignum_to_integer(MagnitudeBytes);
cbor_key_to_term({tag, 3, {bytes, MagnitudeBytes}}) ->
    negative_bignum_to_integer(MagnitudeBytes);
cbor_key_to_term({bytes, Bytes}) ->
    Bytes;
cbor_key_to_term(Value) when is_integer(Value) ->
    Value;
cbor_key_to_term(_Other) ->
    throw(unsupported_map_key).

decode_existing_atom(Name) ->
    try
        binary_to_existing_atom(Name, utf8)
    catch
        error:badarg ->
            throw(unknown_atom_name)
    end.

positive_bignum_to_integer(MagnitudeBytes) ->
    Magnitude = decode_magnitude(MagnitudeBytes),
    case Magnitude > ?UINT64_MAX of
        true -> Magnitude;
        false -> throw(non_canonical_cbor)
    end.

negative_bignum_to_integer(MagnitudeBytes) ->
    Magnitude = decode_magnitude(MagnitudeBytes),
    case Magnitude > ?UINT64_MAX of
        true -> -1 - Magnitude;
        false -> throw(non_canonical_cbor)
    end.

decode_magnitude(<<>>) ->
    throw(non_canonical_cbor);
decode_magnitude(<<0, _/binary>>) ->
    throw(non_canonical_cbor);
decode_magnitude(Bytes) ->
    binary:decode_unsigned(Bytes).

minimal_unsigned_bytes(0) ->
    <<0>>;
minimal_unsigned_bytes(Int) when is_integer(Int), Int > 0 ->
    binary:encode_unsigned(Int).

ensure_not_nan(Value) when Value =:= Value ->
    ok;
ensure_not_nan(_Value) ->
    throw(non_canonical_nan).
