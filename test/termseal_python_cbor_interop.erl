%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_python_cbor_interop).

%=== EXPORTS ===================================================================

-export([ensure_available/0,
         decode_to_normalized_json/1,
         encode_from_normalized_json/1]).


%=== API FUNCTIONS =============================================================

ensure_available() ->
    case run_python(["available"]) of
        {ok, _Output} ->
            ok;
        {skip, Reason} ->
            {skip, Reason};
        {error, Reason} ->
            {skip, io_lib:format("python CBOR interop unavailable: ~ts", [Reason])}
    end.

decode_to_normalized_json(CborBytes) when is_binary(CborBytes) ->
    case run_python(["decode", base64:encode_to_string(CborBytes)]) of
        {ok, Output} ->
            {ok, trim_trailing_newline(Output)};
        Other ->
            Other
    end.

encode_from_normalized_json(Json) when is_binary(Json) ->
    case run_python(["encode", binary_to_list(Json)]) of
        {ok, Output} ->
            {ok, base64:decode(trim_trailing_newline(Output))};
        Other ->
            Other
    end.


%=== INTERNAL FUNCTIONS ========================================================

run_python(Args) ->
    case os:find_executable("python3") of
        false ->
            {skip, "python3 executable not found"};
        Python3 ->
            Port = open_port({spawn_executable, Python3},
                             [binary,
                              exit_status,
                              use_stdio,
                              stderr_to_stdout,
                              hide,
                              {args, ["-c", python_bridge_script() | Args]}]),
            collect_port(Port, [])
    end.

collect_port(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Acc, Data]);
        {Port, {exit_status, 0}} ->
            {ok, iolist_to_binary(Acc)};
        {Port, {exit_status, 2}} ->
            {skip, binary_to_list(iolist_to_binary(Acc))};
        {Port, {exit_status, Status}} ->
            {error, io_lib:format("python exited with status ~B: ~ts",
                                  [Status, iolist_to_binary(Acc)])}
    end.

trim_trailing_newline(Bin) ->
    binary:replace(Bin, <<"\n">>, <<>>, [global]).

python_bridge_script() ->
    string:join(
        ["import base64",
         "import json",
         "import sys",
         "",
         "try:",
         "    import cbor2",
         "except ImportError:",
         "    sys.stderr.write('missing python module cbor2')",
         "    raise SystemExit(2)",
         "",
         "def normalize(value):",
         "    if isinstance(value, cbor2.CBORTag):",
         "        return {'tag': value.tag, 'value': normalize(value.value)}",
         "    if isinstance(value, bytes):",
         "        return {'bytes': value.hex()}",
         "    if isinstance(value, str):",
         "        return {'text': value}",
         "    if isinstance(value, list):",
         "        return {'array': [normalize(item) for item in value]}",
         "    if isinstance(value, dict):",
         "        return {'map': [[normalize(key), normalize(item)] for key, item in value.items()]}",
         "    return value",
         "",
         "def denormalize(value):",
         "    if isinstance(value, dict):",
         "        if set(value.keys()) == {'tag', 'value'}:",
         "            return cbor2.CBORTag(value['tag'], denormalize(value['value']))",
         "        if set(value.keys()) == {'bytes'}:",
         "            return bytes.fromhex(value['bytes'])",
         "        if set(value.keys()) == {'text'}:",
         "            return value['text']",
         "        if set(value.keys()) == {'array'}:",
         "            return [denormalize(item) for item in value['array']]",
         "        if set(value.keys()) == {'map'}:",
         "            result = {}",
         "            for key, item in value['map']:",
         "                result[denormalize(key)] = denormalize(item)",
         "            return result",
         "        raise ValueError('unsupported normalized shape')",
         "    return value",
         "",
         "command = sys.argv[1]",
         "if command == 'available':",
         "    print('ok')",
         "elif command == 'decode':",
         "    encoded = sys.argv[2]",
         "    decoded = cbor2.loads(base64.b64decode(encoded))",
         "    print(json.dumps(normalize(decoded), sort_keys=True, separators=(',', ':')))",
         "elif command == 'encode':",
         "    normalized = json.loads(sys.argv[2])",
         "    encoded = cbor2.dumps(denormalize(normalized), canonical=True)",
         "    print(base64.b64encode(encoded).decode('ascii'))",
         "else:",
         "    sys.stderr.write('unsupported command')",
         "    raise SystemExit(1)"],
        "\n").
