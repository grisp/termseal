%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal).
-moduledoc """
Seal and unseal Erlang terms.

This module preserves the legacy TSF v1 sealing format while exposing the
canonical payload helpers used by newer signing flows.
""".

%=== INCLUDES ==================================================================

-include_lib("public_key/include/public_key.hrl").


%=== EXPORTS ===================================================================

% API functions
-export([canonicalization_id/0]).
-export([signing_payload/1, signing_payload/2]).
-export([signing_request/1, signing_request/2]).
-export([load_private_key/1]).
-export([load_certificates/1]).
-export([seal/1, seal/2]).
-export([unseal/2, unseal/3]).


%=== TYPES =====================================================================

-doc "Canonicalization identifiers accepted by `signing_payload/2`.".
-type canonicalization_id() ::
    erlang_etf_minor_v2_legacy | termseal_cbor_erlang_v1.

-doc "Normalized signer request returned by `signing_request/1,2`.".
-type signing_request() :: #{
    canonicalization_id := canonicalization_id(),
    payload := binary(),
    payload_digest := binary(),
    signing_digest := binary(),
    signing_subject := payload,
    signature_hash := sha256,
    signature_scheme := direct_signature
}.

-doc "Verification result returned by `unseal/2,3`.".
-type unseal_result() ::
    {verified, term()} | {unsigned, term()} | {bad_signature, term()}.


%=== MACROS ====================================================================

-define(MAGIC, "TSF").
-define(VERSION, 1).
-define(SIGHASH, sha256).


%=== API FUNCTIONS =============================================================

-doc "Return the default canonicalization identifier for canonical payloads.".
-spec canonicalization_id() -> termseal_cbor_erlang_v1.
canonicalization_id() ->
    termseal_cbor_erlang:canonicalization_id().

-doc "Encode `Term` using the default canonicalization.".
-spec signing_payload(term()) -> binary().
signing_payload(Term) ->
    signing_payload(Term, canonicalization_id()).

-doc "Encode `Term` using the selected canonicalization.".
-spec signing_payload(term(), canonicalization_id()) -> binary().
signing_payload(Term, erlang_etf_minor_v2_legacy) ->
    term_to_binary(Term, [{minor_version, 2}]);
signing_payload(Term, termseal_cbor_erlang_v1) ->
    case termseal_cbor_erlang:encode(Term) of
        {ok, Payload} -> Payload;
        {error, Reason} -> throw({canonicalization_error, Reason})
    end;
signing_payload(_Term, CanonicalizationId) ->
    throw({unsupported_canonicalization_id, CanonicalizationId}).

-doc "Build a normalized signing request with the default canonicalization.".
-spec signing_request(term()) -> signing_request().
signing_request(Term) ->
    signing_request(Term, canonicalization_id()).

-doc "Build a normalized signing request for `Term`.".
-spec signing_request(term(), canonicalization_id()) -> signing_request().
signing_request(Term, CanonicalizationId) ->
    Payload = signing_payload(Term, CanonicalizationId),
    PayloadDigest = crypto:hash(?SIGHASH, Payload),
    #{
        canonicalization_id => CanonicalizationId,
        payload => Payload,
        payload_digest => PayloadDigest,
        signing_digest => PayloadDigest,
        signing_subject => payload,
        signature_hash => ?SIGHASH,
        signature_scheme => direct_signature
    }.

-doc "Load a private signing key from a PEM file.".
-spec load_private_key(file:filename_all()) -> term().
load_private_key(Filename) ->
    decode_key(Filename, read_file(Filename)).

-doc "Load all certificates from a PEM file.".
-spec load_certificates(file:filename_all()) -> [term()].
load_certificates(Filename) ->
    %TODO: Verify certificates expiration
    %TODO: Verify certification chain
    decode_certs(read_file(Filename)).

-doc "Create an unsigned TSF v1 box.".
-spec seal(term()) -> binary().
seal(Term) ->
    Data = term_to_binary(Term, [{minor_version, 2}]),
    <<
        ?MAGIC,
        ?VERSION:16/unsigned-big-integer,
        0:1, 0:15, % Flags: [SIGNED:0, RESERVED:15]
        (byte_size(Data)):32/unsigned-big-integer,
        Data/binary
    >>.

-doc """
Seal `Term` using the legacy TSF v1 format.

Passing `undefined` produces an unsigned box. Passing a private key produces a
signed TSF v1 box.
""".
-spec seal(term(), undefined | term()) -> binary().
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

-doc "Unseal `Data` using the provided certificate list.".
-spec unseal(binary(), [term()]) -> unseal_result().
unseal(Data, Certs) ->
    unseal(Data, Certs, #{}).

-doc "Unseal `Data` with explicit verification options.".
-spec unseal(binary(), [term()], map()) -> unseal_result().
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


%=== INTERNAL FUNCTIONS ========================================================

read_file(Filename) ->
    case file:read_file(Filename) of
        {error, Reason} -> throw({read_error, Reason, Filename});
        {ok, Data} -> Data
    end.

decode_key(Filename, Data) ->
    Entries = public_key:pem_decode(Data),
    KeyEntries = [E || {T, _, not_encrypted} = E <- Entries,
                  T =:= 'ECPrivateKey' orelse T =:= 'RSAPrivateKey'
                  orelse T =:= 'PrivateKeyInfo'],
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
