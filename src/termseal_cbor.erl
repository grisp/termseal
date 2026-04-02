%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cbor).
-moduledoc """
Encode and decode the deterministic CBOR subset used by `termseal`.

This module knows only CBOR data shapes. Erlang-term-specific mapping rules live
in `termseal_cbor_erlang`.
""".

%=== EXPORTS ===================================================================

-export([encode/1]).
-export([decode/1]).


%=== TYPES =====================================================================

-doc "CBOR values handled by the deterministic codec.".
-type value() :: integer()
               | float()
               | {bytes, binary()}
               | {text, binary()}
               | {array, [value()]}
               | {map, [{value(), value()}]}
               | {tag, non_neg_integer(), value()}.


%=== MACROS ====================================================================

-define(UINT32_MAX, 16#FFFFFFFF).
-define(UINT64_MAX, 16#FFFFFFFFFFFFFFFF).


%=== API FUNCTIONS =============================================================

-doc "Encode a CBOR value using deterministic encoding rules.".
-spec encode(value()) -> {ok, binary()} | {error, term()}.
encode(Value) ->
    try
        {ok, iolist_to_binary(encode_value(Value))}
    catch
        throw:Reason -> {error, Reason}
    end.

-doc "Decode a canonical CBOR value.".
-spec decode(binary()) -> {ok, value()} | {error, term()}.
decode(Bin) when is_binary(Bin) ->
    try
        {Value, <<>>, _Consumed} = decode_item(Bin),
        {ok, Value}
    catch
        throw:Reason -> {error, Reason}
    end;
decode(_Other) ->
    {error, invalid_cbor}.


%=== INTERNAL FUNCTIONS ========================================================

encode_value(Value) when is_integer(Value), Value >= 0 ->
    encode_argument(0, Value);
encode_value(Value) when is_integer(Value) ->
    encode_argument(1, -1 - Value);
encode_value(Value) when is_float(Value) ->
    <<16#FB, Value:64/float-big>>;
encode_value({bytes, Bytes}) when is_binary(Bytes) ->
    [encode_argument(2, byte_size(Bytes)), Bytes];
encode_value({text, Text}) when is_binary(Text) ->
    validate_utf8(Text),
    [encode_argument(3, byte_size(Text)), Text];
encode_value({array, Values}) when is_list(Values) ->
    [encode_argument(4, length(Values)),
     [encode_value(Value) || Value <- Values]];
encode_value({map, Pairs}) when is_list(Pairs) ->
    encode_map(Pairs);
encode_value({tag, Tag, Value}) when is_integer(Tag), Tag >= 0 ->
    [encode_argument(6, Tag), encode_value(Value)];
encode_value(_Other) ->
    throw(unsupported_cbor_value).

encode_map(Pairs) ->
    EncodedPairs = [{iolist_to_binary(encode_value(Key)),
                     iolist_to_binary(encode_value(Value))}
                    || {Key, Value} <- Pairs],
    SortedPairs = lists:sort(fun compare_key_order/2, EncodedPairs),
    ensure_unique_sorted_keys(SortedPairs),
    [encode_argument(5, length(SortedPairs)),
     [[KeyBytes, ValueBytes] || {KeyBytes, ValueBytes} <- SortedPairs]].

encode_argument(MajorType, Arg) when is_integer(Arg), Arg >= 0, Arg < 24 ->
    <<MajorType:3, Arg:5>>;
encode_argument(MajorType, Arg) when is_integer(Arg), Arg =< 16#FF ->
    <<MajorType:3, 24:5, Arg:8>>;
encode_argument(MajorType, Arg) when is_integer(Arg), Arg =< 16#FFFF ->
    <<MajorType:3, 25:5, Arg:16/unsigned-big>>;
encode_argument(MajorType, Arg) when is_integer(Arg), Arg =< ?UINT32_MAX ->
    <<MajorType:3, 26:5, Arg:32/unsigned-big>>;
encode_argument(MajorType, Arg) when is_integer(Arg), Arg =< ?UINT64_MAX ->
    <<MajorType:3, 27:5, Arg:64/unsigned-big>>;
encode_argument(_MajorType, _Arg) ->
    throw(unsupported_cbor_value).

validate_utf8(Text) ->
    try unicode:characters_to_binary(Text, utf8, utf8) of
        Text ->
            ok;
        _Other ->
            throw(invalid_utf8)
    catch
        error:badarg ->
            throw(invalid_utf8)
    end.

decode_item(Bin) when is_binary(Bin) ->
    {Value, Rest} = decode_item_1(Bin),
    ConsumedSize = byte_size(Bin) - byte_size(Rest),
    {Value, Rest, binary:part(Bin, 0, ConsumedSize)}.

decode_item_1(<<>>) ->
    throw(invalid_cbor);
decode_item_1(<<Initial, Rest/binary>>) ->
    MajorType = Initial bsr 5,
    Additional = Initial band 16#1F,
    case MajorType of
        0 ->
            {Arg, Tail} = decode_argument(Additional, Rest),
            {Arg, Tail};
        1 ->
            {Arg, Tail} = decode_argument(Additional, Rest),
            {-1 - Arg, Tail};
        2 ->
            {Length, Tail0} = decode_length(Additional, Rest),
            <<Bytes:Length/binary, Tail/binary>> = ensure_binary(Tail0, Length),
            {{bytes, Bytes}, Tail};
        3 ->
            {Length, Tail0} = decode_length(Additional, Rest),
            <<Text:Length/binary, Tail/binary>> = ensure_binary(Tail0, Length),
            validate_utf8(Text),
            {{text, Text}, Tail};
        4 ->
            {Length, Tail0} = decode_length(Additional, Rest),
            decode_array(Length, Tail0, []);
        5 ->
            {Length, Tail0} = decode_length(Additional, Rest),
            decode_map(Length, Tail0, undefined, []);
        6 ->
            {Tag, Tail0} = decode_argument(Additional, Rest),
            {Value, Tail} = decode_item_1(Tail0),
            {{tag, Tag, Value}, Tail};
        7 ->
            decode_simple_or_float(Additional, Rest)
    end.

decode_array(0, Rest, Acc) ->
    {{array, lists:reverse(Acc)}, Rest};
decode_array(Length, Rest0, Acc) ->
    {Value, Rest} = decode_item_1(Rest0),
    decode_array(Length - 1, Rest, [Value | Acc]).

decode_map(0, Rest, _PreviousKeyBytes, Acc) ->
    {{map, lists:reverse(Acc)}, Rest};
decode_map(Length, Rest0, PreviousKeyBytes, Acc) ->
    {Key, Rest1, KeyBytes} = decode_item(Rest0),
    ensure_map_key_order(PreviousKeyBytes, KeyBytes),
    {Value, Rest2} = decode_item_1(Rest1),
    decode_map(Length - 1, Rest2, KeyBytes, [{Key, Value} | Acc]).

decode_simple_or_float(27, <<Bits:64/unsigned-big, Rest/binary>>) ->
    case is_nan_bits(Bits) of
        true ->
            throw(non_canonical_nan);
        false ->
            <<Float:64/float-big>> = <<Bits:64/unsigned-big>>,
            {Float, Rest}
    end;
decode_simple_or_float(27, _Short) ->
    throw(invalid_cbor);
decode_simple_or_float(_Additional, _Rest) ->
    throw(non_canonical_cbor).

is_nan_bits(Bits) ->
    Exponent = (Bits bsr 52) band 16#7FF,
    Mantissa = Bits band 16#FFFFFFFFFFFFF,
    Exponent =:= 16#7FF andalso Mantissa =/= 0.

decode_length(Additional, Rest) ->
    decode_argument(Additional, Rest).

decode_argument(Additional, Rest) when Additional < 24 ->
    {Additional, Rest};
decode_argument(24, <<Arg:8, Rest/binary>>) when Arg >= 24 ->
    {Arg, Rest};
decode_argument(24, <<_Arg:8, _Rest/binary>>) ->
    throw(non_canonical_cbor);
decode_argument(24, _Short) ->
    throw(invalid_cbor);
decode_argument(25, <<Arg:16/unsigned-big, Rest/binary>>) when Arg >= 16#100 ->
    {Arg, Rest};
decode_argument(25, <<_Arg:16/unsigned-big, _Rest/binary>>) ->
    throw(non_canonical_cbor);
decode_argument(25, _Short) ->
    throw(invalid_cbor);
decode_argument(26, <<Arg:32/unsigned-big, Rest/binary>>) when Arg >= 16#10000 ->
    {Arg, Rest};
decode_argument(26, <<_Arg:32/unsigned-big, _Rest/binary>>) ->
    throw(non_canonical_cbor);
decode_argument(26, _Short) ->
    throw(invalid_cbor);
decode_argument(27, <<Arg:64/unsigned-big, Rest/binary>>) when Arg >= 16#100000000 ->
    {Arg, Rest};
decode_argument(27, <<_Arg:64/unsigned-big, _Rest/binary>>) ->
    throw(non_canonical_cbor);
decode_argument(27, _Short) ->
    throw(invalid_cbor);
decode_argument(31, _Rest) ->
    throw(non_canonical_cbor);
decode_argument(_Additional, _Rest) ->
    throw(invalid_cbor).

ensure_binary(Bin, Length) when byte_size(Bin) >= Length ->
    Bin;
ensure_binary(_Bin, _Length) ->
    throw(invalid_cbor).

compare_key_order({KeyA, _ValueA}, {KeyB, _ValueB}) ->
    compare_key_bytes(KeyA, KeyB) =:= lt.

compare_key_bytes(KeyA, KeyB) ->
    case byte_size(KeyA) - byte_size(KeyB) of
        Negative when Negative < 0 ->
            lt;
        Positive when Positive > 0 ->
            gt;
        0 ->
            if
                KeyA < KeyB -> lt;
                KeyA > KeyB -> gt;
                true -> eq
            end
    end.

ensure_unique_sorted_keys([]) ->
    ok;
ensure_unique_sorted_keys([_Only]) ->
    ok;
ensure_unique_sorted_keys([{KeyA, _ValueA}, {KeyB, _ValueB} | Rest]) ->
    case compare_key_bytes(KeyA, KeyB) of
        eq ->
            throw(duplicate_canonical_map_key);
        lt ->
            ensure_unique_sorted_keys([{KeyB, undefined} | Rest]);
        gt ->
            throw(non_canonical_cbor)
    end.

ensure_map_key_order(undefined, _Current) ->
    ok;
ensure_map_key_order(Previous, Current) ->
    case compare_key_bytes(Previous, Current) of
        lt ->
            ok;
        eq ->
            throw(duplicate_canonical_map_key);
        gt ->
            throw(non_canonical_cbor)
    end.
