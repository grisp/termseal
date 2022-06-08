-module(termseal).


%--- Includes ------------------------------------------------------------------

-include_lib("public_key/include/public_key.hrl").


%--- Exports -------------------------------------------------------------------

% API functions
-export([load_private_key/1]).
-export([load_certificates/1]).
-export([seal/1, seal/2]).
-export([unseal/2, unseal/3]).


%--- Macros --------------------------------------------------------------------

-define(MAGIC, "TSF").
-define(VERSION, 1).
-define(SIGHASH, sha256).


%--- API Functions -------------------------------------------------------------

load_private_key(Filename) ->
    decode_key(Filename, read_file(Filename)).

load_certificates(Filename) ->
    %TODO: Verify certificates expiration
    %TODO: Verify certification chain
    decode_certs(read_file(Filename)).

seal(Term) ->
    Data = term_to_binary(Term, [{minor_version, 2}]),
    <<
        ?MAGIC,
        ?VERSION:16/unsigned-big-integer,
        0:1, 0:15, % Flags: [SIGNED:0, RESERVED:15]
        (byte_size(Data)):32/unsigned-big-integer,
        Data/binary
    >>.

seal(Term, undefined) -> seal(Term);
seal(Term, Key) ->
    Data = term_to_binary(Term, [{minor_version, 2}]),
    Sig = public_key:sign(Data, ?SIGHASH, Key),
    <<
        ?MAGIC,
        ?VERSION:16/unsigned-big-integer,
        1:1, 0:15, % Flags: [SIGNED:1, RESERVED:15]
        (byte_size(Sig)):32/unsigned-big-integer,
        Sig/binary,
        (byte_size(Data)):32/unsigned-big-integer,
        Data/binary
    >>.

unseal(Data, Certs) ->
    unseal(Data, Certs, #{}).

unseal(<<?MAGIC,?VERSION:16/unsigned-big-integer, Body/binary>>, Certs, Opts) ->
    case Body of
        <<1:1, _:15,
         SigLen:32/unsigned-big-integer, Sig:SigLen/binary,
         DataLen:32/unsigned-big-integer, Data:DataLen/binary>> ->
            unseal_signed(Data, Sig, Certs, Opts);
        <<0:1, _:15,
         DataLen:32/unsigned-big-integer, Data:DataLen/binary>> ->
            unseal_unsigned(Data, Opts);
        _Other ->
            throw(bad_seal_format)
    end;
unseal(<<?MAGIC,Ver:16/unsigned-big-integer, _/binary>>, _Certs, _Opts) ->
    throw({usupported_seal_version, Ver});
unseal(_Data, _Certs, _Opts) ->
    throw(invalid_seal_data).


%--- Internal Functions --------------------------------------------------------

read_file(Filename) ->
    case file:read_file(Filename) of
        {error, Reason} -> throw({read_error, Reason, Filename});
        {ok, Data} -> Data
    end.

decode_key(Filename, Data) ->
    Entries = public_key:pem_decode(Data),
    KeyEntries = [E || {T, _, not_encrypted} = E <- Entries,
                  T =:= 'ECPrivateKey' orelse T =:= 'RSAPrivateKey'],
    case KeyEntries  of
        [] -> throw({key_not_found, Filename});
        [KeyEntry] -> public_key:pem_entry_decode(KeyEntry);
        [_|_] -> throw({too_many_keys, Filename})
    end.

decode_certs(Data) ->
    Entries = public_key:pem_decode(Data),
    [public_key:pkix_decode_cert(Der, otp)
     || {'Certificate', Der, not_encrypted} <- Entries].

cert_to_pubkey(Cert) ->
    #'OTPCertificate'{
        tbsCertificate = #'OTPTBSCertificate'{
            subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
                algorithm = #'PublicKeyAlgorithm'{
                    parameters = ECPublicKeyParameters
                },
                subjectPublicKey = ECPublicKeyData
            }
        }
    } = Cert,
    case ECPublicKeyData of
        #'RSAPublicKey'{} -> ECPublicKeyData;
        #'ECPoint'{} -> {ECPublicKeyData, ECPublicKeyParameters}
    end.

unseal_unsigned(Data, #{allow_unsigned := true} = Opts) ->
    {unsigned, unserialize(Data, Opts)};
unseal_unsigned(_Data, _Opts) ->
    throw(unsigned_seal_not_allowed).

unseal_signed(Data, Sig, Certs, Opts) ->
    AllowBadSig = maps:get(allow_bad_signature, Opts, false),
    case {AllowBadSig, verify_data(Data, Sig, Certs)} of
        {false, false} -> throw(bad_signature);
        {true, false} -> {bad_signature, unserialize(Data, Opts)};
        {_, true} -> {verified, unserialize(Data, Opts)}
    end.

unserialize(Data, #{safe := true}) -> binary_to_term(Data, [safe]);
unserialize(Data, _Opts) -> binary_to_term(Data, []).

verify_data(_Data, _Sig, []) -> false;
verify_data(Data, Sig, [Cert | Rest]) ->
    PubKey = cert_to_pubkey(Cert),
    case public_key:verify(Data, ?SIGHASH, Sig, PubKey) of
        false -> verify_data(Data, Sig, Rest);
        true -> true
    end.