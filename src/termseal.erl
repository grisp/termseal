%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal).
-moduledoc """
Seal and unseal Erlang terms.

This module preserves the legacy TSF v1 sealing format while exposing the
canonical form helpers used by newer signing flows.
""".

%=== INCLUDES ==================================================================

-include_lib("public_key/include/public_key.hrl").


%=== EXPORTS ===================================================================

% API functions
-export([canonical_form/1, canonical_form/2]).
-export([load_private_key/1]).
-export([load_certificates/1]).
-export([seal/1, seal/2]).
-export([unseal/2, unseal/3]).


%=== TYPES =====================================================================

-doc "Canonicalization identifiers accepted by `canonical_form/2`.".
-type canonicalization_id() ::
    erlang_etf_minor_v2_legacy | termseal_cbor_erlang_v1.

-doc "Digest algorithms accepted by CMS signer specifications.".
-type signature_hash() :: sha256 | sha384 | sha512.

-doc "Signature schemes accepted by CMS signer specifications.".
-type signature_scheme() :: ecdsa | rsa_pkcs1_v1_5 | rsa_pss.

-type callback_request() :: #{
    canonicalization_id := canonicalization_id(),
    data := binary(),
    signature_digest := binary(),
    signature_hash := signature_hash(),
    signature_scheme := signature_scheme()
}.

-doc "Verification result returned by `unseal/2,3`.".
-type unseal_result() ::
    {verified, term()} | {unsigned, term()} | {bad_signature, term()}.


%=== MACROS ====================================================================

-define(MAGIC, "TSF").
-define(VERSION, 1).
-define(DEFAULT_SIGHASH, sha256).
-define(DEFAULT_CANONIZATION_ID, termseal_cbor_erlang_v1).


%=== API FUNCTIONS =============================================================

-doc "Encode `Term` using the default canonicalization.".
-spec canonical_form(term()) -> binary().
canonical_form(Term) ->
    canonical_form(Term, ?DEFAULT_CANONIZATION_ID).

-doc "Encode `Term` using the selected canonicalization.".
-spec canonical_form(term(), canonicalization_id()) -> binary().
canonical_form(Term, erlang_etf_minor_v2_legacy) ->
    term_to_binary(Term, [{minor_version, 2}]);
canonical_form(Term, termseal_cbor_erlang_v1) ->
    case termseal_cbor_erlang:encode(Term) of
        {ok, Payload} -> Payload;
        {error, Reason} -> throw({canonicalization_error, Reason})
    end;
canonical_form(_Term, CanonicalizationId) ->
    throw({unsupported_canonicalization_id, CanonicalizationId}).

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
signed TSF v1 box. Passing a signer-spec map produces a CMS `SignedData` box.
""".
-spec seal(term(), undefined | term()) -> binary().
seal(Term, undefined) -> seal(Term);
seal(Term, SignerSpec) when is_map(SignerSpec) ->
    seal_cms(Term, SignerSpec);
seal(Term, Key) ->
    Data = canonical_form(Term, erlang_etf_minor_v2_legacy),
    Sig = public_key:sign(Data, ?DEFAULT_SIGHASH, Key),
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

seal_cms(Term, SignerSpec) ->
    CanonicalizationId = maps:get(canonicalization_id, SignerSpec, ?DEFAULT_CANONIZATION_ID),
    SignatureHash = validate_signature_hash(maps:get(signature_hash, SignerSpec, ?DEFAULT_SIGHASH)),
    SignatureScheme = resolve_signature_scheme(SignerSpec),
    Request = cms_callback_request(Term, CanonicalizationId, SignatureHash, SignatureScheme),
    Response = cms_signer_response(Request, SignerSpec),
    build_cms_signed_data(Request, Response).

-spec cms_callback_request(
    term(),
    canonicalization_id(),
    signature_hash(),
    signature_scheme()
) -> callback_request().
cms_callback_request(Term, CanonicalizationId, SignatureHash, SignatureScheme) ->
    Data = cms_signed_content(canonical_form(Term, CanonicalizationId), CanonicalizationId),
    #{
        canonicalization_id => CanonicalizationId,
        data => Data,
        signature_digest => crypto:hash(SignatureHash, Data),
        signature_hash => SignatureHash,
        signature_scheme => SignatureScheme
    }.

cms_signed_content(CanonicalForm, CanonicalizationId) ->
    % Build the CMS envelope using CBOR.
    Value = {map, [{{text, <<"payload">>}, {bytes, CanonicalForm}},
                   {{text, <<"canonicalization_id">>},
                    {text, atom_to_binary(CanonicalizationId, utf8)}}]},
    case termseal_cbor:encode(Value) of
        {ok, SignedContent} -> SignedContent;
        {error, Reason} -> throw({canonicalization_error, Reason})
    end.

cms_signer_response(Request, #{signer_key := Key, signer_cert := SignerCertDer} = SignerSpec) ->
    NormalizedResponse = #{
        signature => sign_with_scheme(Request, Key),
        signer_cert => validate_cert_der(SignerCertDer),
        chain => validate_cert_chain(maps:get(chain, SignerSpec, []))
    },
    ensure_valid_signer_response(Request, NormalizedResponse);
cms_signer_response(Request, #{signer_fun := SignerFun}) when is_function(SignerFun, 1) ->
    Response = SignerFun(Request),
    ensure_valid_signer_response(Request, validate_signer_response(Response));
cms_signer_response(_Request, _SignerSpec) ->
    throw(invalid_signer_spec).

validate_signer_response(#{signature := Signature, signer_cert := SignerCertDer} = Response)
  when is_binary(Signature) ->
    #{
        signature => Signature,
        signer_cert => validate_cert_der(SignerCertDer),
        chain => validate_cert_chain(maps:get(chain, Response, []))
    };
validate_signer_response(_Response) ->
    throw(invalid_signer_response).

validate_cert_der(SignerCertDer) when is_binary(SignerCertDer) ->
    SignerCertDer;
validate_cert_der(_Other) ->
    throw(invalid_signer_response).

validate_cert_chain(Chain) when is_list(Chain) ->
    [validate_cert_der(CertDer) || CertDer <- Chain];
validate_cert_chain(_Other) ->
    throw(invalid_signer_response).

ensure_valid_signer_response(Request,
                             #{signature := Signature,
                               signer_cert := SignerCertDer} = Response) ->
    SignerCert = decode_plain_cert(SignerCertDer),
    validate_signature_scheme_for_cert(
        maps:get(signature_scheme, Request),
        SignerCert
    ),
    case verify_signature(Request, Signature, SignerCertDer) of
        true -> Response;
        false -> throw(invalid_signer_response)
    end.

build_cms_signed_data(#{data := SignedContent,
                        signature_hash := SignatureHash,
                        signature_scheme := SignatureScheme},
                      #{signature := Signature,
                        signer_cert := SignerCertDer,
                        chain := ChainDers}) ->
    SignerCert = decode_plain_cert(SignerCertDer),
    ChainCerts = [decode_plain_cert(CertDer) || CertDer <- ChainDers],
    Certificates = [{certificate, Cert} || Cert <- [SignerCert | ChainCerts]],
    SignerInfo = build_cms_signer_info(
        SignerCert,
        Signature,
        SignatureHash,
        SignatureScheme
    ),
    ContentInfo = #'ContentInfo'{
        contentType = ?'id-signedData',
        content = #'SignedData'{
            version = v1,
            digestAlgorithms = [digest_algorithm_identifier(SignatureHash)],
            encapContentInfo = #'EncapsulatedContentInfo'{
                eContentType = ?'data',
                eContent = SignedContent
            },
            certificates = Certificates,
            signerInfos = [SignerInfo]
        }
    },
    public_key:der_encode('ContentInfo', ContentInfo).

build_cms_signer_info(#'Certificate'{
                          tbsCertificate = #'TBSCertificate'{
                              issuer = Issuer,
                              serialNumber = SerialNumber
                          }
                      } = SignerCert,
                      Signature,
                      SignatureHash,
                      SignatureScheme) ->
    #'SignerInfo'{
        version = v1,
        sid = {issuerAndSerialNumber,
               #'IssuerAndSerialNumber'{
                   issuer = Issuer,
                   serialNumber = SerialNumber
               }},
        digestAlgorithm = digest_algorithm_identifier(SignatureHash),
        signatureAlgorithm = signature_algorithm_identifier(
            SignerCert,
            SignatureScheme,
            SignatureHash
        ),
        signature = Signature
    }.

digest_algorithm_identifier(sha256) ->
    #'DigestAlgorithmIdentifier'{algorithm = ?'id-sha256'};
digest_algorithm_identifier(sha384) ->
    #'DigestAlgorithmIdentifier'{algorithm = ?'id-sha384'};
digest_algorithm_identifier(sha512) ->
    #'DigestAlgorithmIdentifier'{algorithm = ?'id-sha512'}.

signature_algorithm_identifier(SignerCert, SignatureScheme, SignatureHash) ->
    validate_signature_scheme_for_cert(SignatureScheme, SignerCert),
    signature_algorithm_identifier(SignatureScheme, SignatureHash).

signature_algorithm_identifier(rsa_pkcs1_v1_5, sha256) ->
    #'SignatureAlgorithmIdentifier'{
        algorithm = ?'sha256WithRSAEncryption',
        parameters = {asn1_OPENTYPE, <<5, 0>>}
    };
signature_algorithm_identifier(rsa_pkcs1_v1_5, sha384) ->
    #'SignatureAlgorithmIdentifier'{
        algorithm = ?'sha384WithRSAEncryption',
        parameters = {asn1_OPENTYPE, <<5, 0>>}
    };
signature_algorithm_identifier(rsa_pkcs1_v1_5, sha512) ->
    #'SignatureAlgorithmIdentifier'{
        algorithm = ?'sha512WithRSAEncryption',
        parameters = {asn1_OPENTYPE, <<5, 0>>}
    };
signature_algorithm_identifier(ecdsa, sha256) ->
    #'SignatureAlgorithmIdentifier'{algorithm = ?'ecdsa-with-SHA256'};
signature_algorithm_identifier(ecdsa, sha384) ->
    #'SignatureAlgorithmIdentifier'{algorithm = ?'ecdsa-with-SHA384'};
signature_algorithm_identifier(ecdsa, sha512) ->
    #'SignatureAlgorithmIdentifier'{algorithm = ?'ecdsa-with-SHA512'};
signature_algorithm_identifier(rsa_pss, SignatureHash) ->
    #'SignatureAlgorithmIdentifier'{
        algorithm = ?'id-RSASSA-PSS',
        parameters = {asn1_OPENTYPE, rsa_pss_parameters_der(SignatureHash)}
    }.

rsa_pss_parameters_der(SignatureHash) ->
    public_key:der_encode(
        'RSASSA-PSS-params',
        #'RSASSA-PSS-params'{
            hashAlgorithm = #'HashAlgorithm'{
                algorithm = hash_algorithm_oid(SignatureHash),
                parameters = 'NULL'
            },
            maskGenAlgorithm = #'MaskGenAlgorithm'{
                algorithm = ?'id-mgf1',
                parameters = #'HashAlgorithm'{
                    algorithm = hash_algorithm_oid(SignatureHash),
                    parameters = 'NULL'
                }
            },
            saltLength = hash_size(SignatureHash),
            trailerField = 1
        }
    ).

hash_algorithm_oid(sha256) ->
    ?'id-sha256';
hash_algorithm_oid(sha384) ->
    ?'id-sha384';
hash_algorithm_oid(sha512) ->
    ?'id-sha512'.

hash_size(sha256) ->
    32;
hash_size(sha384) ->
    48;
hash_size(sha512) ->
    64.

decode_plain_cert(Der) ->
    public_key:pkix_decode_cert(Der, plain).

sign_with_scheme(#{signature_digest := SignatureDigest,
                   signature_hash := SignatureHash,
                   signature_scheme := SignatureScheme},
                 Key) ->
    public_key:sign(
        {digest, SignatureDigest},
        SignatureHash,
        Key,
        signature_options(SignatureScheme, SignatureHash)
    ).

verify_signature(#{signature_digest := SignatureDigest,
                   signature_hash := SignatureHash,
                   signature_scheme := SignatureScheme},
                 Signature,
                 SignerCertDer) ->
    SignerCert = public_key:pkix_decode_cert(SignerCertDer, otp),
    PubKey = cert_to_pubkey(SignerCert),
    public_key:verify(
        {digest, SignatureDigest},
        SignatureHash,
        Signature,
        PubKey,
        signature_options(SignatureScheme, SignatureHash)
    ).

signature_options(rsa_pss, SignatureHash) ->
    [{rsa_padding, rsa_pkcs1_pss_padding},
     {rsa_pss_saltlen, hash_size(SignatureHash)},
     {rsa_mgf1_md, SignatureHash}];
signature_options(rsa_pkcs1_v1_5, _SignatureHash) ->
    [];
signature_options(ecdsa, _SignatureHash) ->
    [].

resolve_signature_scheme(#{signature_scheme := SignatureScheme}) ->
    validate_signature_scheme(SignatureScheme);
resolve_signature_scheme(#{signer_key := Key}) ->
    default_signature_scheme(private_key_algorithm(Key));
resolve_signature_scheme(#{signer_fun := _SignerFun}) ->
    throw(signature_scheme_required);
resolve_signature_scheme(_SignerSpec) ->
    throw(invalid_signer_spec).

default_signature_scheme(rsa) ->
    rsa_pss;
default_signature_scheme(ec) ->
    ecdsa.

private_key_algorithm(#'RSAPrivateKey'{}) ->
    rsa;
private_key_algorithm(#'ECPrivateKey'{}) ->
    ec;
private_key_algorithm(_Key) ->
    throw(unsupported_signer_key_type).

validate_signature_scheme_for_cert(SignatureScheme,
                                   #'Certificate'{
                                       tbsCertificate = #'TBSCertificate'{
                                           subjectPublicKeyInfo = #'SubjectPublicKeyInfo'{
                                               algorithm = #'AlgorithmIdentifier'{
                                                   algorithm = Algorithm
                                               }
                                           }
                                       }
                                   }) ->
    case {SignatureScheme, Algorithm} of
        {ecdsa, ?'id-ecPublicKey'} -> ok;
        {rsa_pkcs1_v1_5, ?'rsaEncryption'} -> ok;
        {rsa_pss, ?'rsaEncryption'} -> ok;
        _ -> throw(unsupported_signature_scheme)
    end.

validate_signature_hash(sha256) ->
    sha256;
validate_signature_hash(sha384) ->
    sha384;
validate_signature_hash(sha512) ->
    sha512;
validate_signature_hash(_Other) ->
    throw(unsupported_signature_hash).

validate_signature_scheme(ecdsa) ->
    ecdsa;
validate_signature_scheme(rsa_pkcs1_v1_5) ->
    rsa_pkcs1_v1_5;
validate_signature_scheme(rsa_pss) ->
    rsa_pss;
validate_signature_scheme(_Other) ->
    throw(unsupported_signature_scheme).

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
    case public_key:verify(Data, ?DEFAULT_SIGHASH, Sig, PubKey) of
        false -> verify_data(Data, Sig, Rest);
        true -> true
    end.
