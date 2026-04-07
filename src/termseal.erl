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
unseal(Data, Certs, Opts) when is_binary(Data), is_list(Certs), is_map(Opts) ->
    unseal_cms(Data, Certs, Opts);
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

unseal_cms(Data, Certs, Opts) ->
    NormalizedOpts = normalize_unseal_opts(Certs, Opts),
    Parsed = parse_cms_seal(Data, NormalizedOpts),
    case verify_cms_seal(Parsed, NormalizedOpts) of
        true ->
            {verified, maps:get(term, Parsed)};
        false ->
            cms_bad_signature_result(Parsed, NormalizedOpts)
    end.

normalize_unseal_opts(Certs, Opts) ->
    TrustedSignerCerts =
        case maps:find(trusted_signer_certs, Opts) of
            error ->
                Certs;
            {ok, _TrustedSignerCerts} when Certs =/= [] ->
                throw(conflicting_trusted_signer_certs);
            {ok, TrustedSignerCerts0} ->
                TrustedSignerCerts0
        end,
    TrustAnchors = maps:get(trust_anchors, Opts, []),
    UnsealMode = maps:get(
        unseal_mode,
        Opts,
        default_unseal_mode(TrustedSignerCerts, TrustAnchors)
    ),
    #{
        trusted_signer_certs => TrustedSignerCerts,
        trust_anchors => TrustAnchors,
        unseal_mode => UnsealMode,
        allow_bad_signature => maps:get(allow_bad_signature, Opts, false),
        validate_signer_cert_expiration =>
            maps:get(validate_signer_cert_expiration, Opts, false),
        disable_expiration_validation =>
            maps:get(disable_expiration_validation, Opts, false),
        safe => maps:get(safe, Opts, false)
    }.

default_unseal_mode([], [_|_]) ->
    trust_anchor;
default_unseal_mode([_|_], []) ->
    direct_cert;
default_unseal_mode([_|_], [_|_]) ->
    both;
default_unseal_mode([], []) ->
    direct_cert.

parse_cms_seal(Data, Opts) ->
    ContentInfo = decode_cms_content_info(Data),
    #'ContentInfo'{contentType = ?'id-signedData',
                   content = SignedData} = ContentInfo,
    SignerInfo = cms_signer_info(SignedData),
    SignedContent = cms_signed_content_data(SignedData),
    EmbeddedCerts = cms_embedded_certificate_ders(SignedData),
    SignerCertDer = signer_cert_der(SignerInfo, EmbeddedCerts),
    ChainDers = signer_chain_ders(SignerCertDer, EmbeddedCerts),
    {SignatureHash, SignatureScheme} = cms_signature_metadata(SignerInfo),
    SignatureDigest = cms_signature_digest(
        SignedContent,
        SignedData#'SignedData'.encapContentInfo#'EncapsulatedContentInfo'.eContentType,
        SignerInfo,
        SignatureHash
    ),
    {CanonicalizationId, CanonicalForm} = decode_cms_envelope(SignedContent),
    Term = decode_canonical_form(CanonicalizationId, CanonicalForm, Opts),
    #{
        term => Term,
        signer_cert_der => SignerCertDer,
        chain_ders => ChainDers,
        signature => SignerInfo#'SignerInfo'.signature,
        signature_request => #{
            signature_digest => SignatureDigest,
            signature_hash => SignatureHash,
            signature_scheme => SignatureScheme
        }
    }.

decode_cms_content_info(Data) ->
    try
        ContentInfo = public_key:der_decode('ContentInfo', Data),
        case ContentInfo of
            #'ContentInfo'{contentType = ?'id-signedData'} ->
                ContentInfo;
            _Other ->
                throw(invalid_seal_data)
        end
    catch
        _:_ ->
            throw(invalid_seal_data)
    end.

cms_signer_info(#'SignedData'{signerInfos = [SignerInfo]}) ->
    SignerInfo;
cms_signer_info(_Other) ->
    throw(invalid_seal_data).

cms_signed_content_data(#'SignedData'{
                           encapContentInfo =
                               #'EncapsulatedContentInfo'{
                                   eContentType = ?'data',
                                   eContent = SignedContent
                               }
                       }) when is_binary(SignedContent) ->
    SignedContent;
cms_signed_content_data(_Other) ->
    throw(invalid_seal_data).

cms_embedded_certificate_ders(#'SignedData'{certificates = Certificates}) when is_list(Certificates) ->
    [public_key:der_encode('Certificate', Cert)
     || {certificate, Cert} <- Certificates];
cms_embedded_certificate_ders(_Other) ->
    throw(invalid_seal_data).

signer_cert_der(#'SignerInfo'{
                    sid = {issuerAndSerialNumber,
                           #'IssuerAndSerialNumber'{
                               issuer = Issuer,
                               serialNumber = SerialNumber
                           }}
                },
                EmbeddedCerts) ->
    case [Der || Der <- EmbeddedCerts,
                 cert_matches_issuer_and_serial(Der, Issuer, SerialNumber)] of
        [SignerCertDer] -> SignerCertDer;
        _ -> throw(invalid_seal_data)
    end;
signer_cert_der(_SignerInfo, _EmbeddedCerts) ->
    throw(invalid_seal_data).

signer_chain_ders(SignerCertDer, EmbeddedCerts) ->
    [Der || Der <- EmbeddedCerts, Der =/= SignerCertDer].

cert_matches_issuer_and_serial(Der, Issuer, SerialNumber) ->
    #'Certificate'{
        tbsCertificate = #'TBSCertificate'{
            issuer = CertIssuer,
            serialNumber = CertSerialNumber
        }
    } = decode_plain_cert(Der),
    CertIssuer =:= Issuer andalso CertSerialNumber =:= SerialNumber.

cert_subject(Der) ->
    #'Certificate'{
        tbsCertificate = #'TBSCertificate'{
            subject = Subject
        }
    } = decode_plain_cert(Der),
    Subject.

cert_issuer(Der) ->
    #'Certificate'{
        tbsCertificate = #'TBSCertificate'{
            issuer = Issuer
        }
    } = decode_plain_cert(Der),
    Issuer.

cms_signature_metadata(#'SignerInfo'{
                           digestAlgorithm = DigestAlgorithm,
                           signatureAlgorithm = SignatureAlgorithm
                       }) ->
    SignatureHash = digest_hash(DigestAlgorithm),
    {SignatureScheme, SignatureAlgorithmHash} =
        signature_algorithm_metadata(SignatureAlgorithm),
    case SignatureAlgorithmHash =:= undefined
            orelse SignatureHash =:= SignatureAlgorithmHash of
        true -> {SignatureHash, SignatureScheme};
        false -> throw(invalid_seal_data)
    end.

digest_hash(#'DigestAlgorithmIdentifier'{algorithm = ?'id-sha256'}) ->
    sha256;
digest_hash(#'DigestAlgorithmIdentifier'{algorithm = ?'id-sha384'}) ->
    sha384;
digest_hash(#'DigestAlgorithmIdentifier'{algorithm = ?'id-sha512'}) ->
    sha512;
digest_hash(_Other) ->
    throw(invalid_seal_data).

signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?rsaEncryption
                             }) ->
    {rsa_pkcs1_v1_5, undefined};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'sha256WithRSAEncryption'
                             }) ->
    {rsa_pkcs1_v1_5, sha256};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'sha384WithRSAEncryption'
                             }) ->
    {rsa_pkcs1_v1_5, sha384};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'sha512WithRSAEncryption'
                             }) ->
    {rsa_pkcs1_v1_5, sha512};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'ecdsa-with-SHA256'
                             }) ->
    {ecdsa, sha256};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'ecdsa-with-SHA384'
                             }) ->
    {ecdsa, sha384};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'ecdsa-with-SHA512'
                             }) ->
    {ecdsa, sha512};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'id-ecPublicKey'
                             }) ->
    {ecdsa, undefined};
signature_algorithm_metadata(#'SignatureAlgorithmIdentifier'{
                                 algorithm = ?'id-RSASSA-PSS',
                                 parameters = {asn1_OPENTYPE, ParamsDer}
                             }) when is_binary(ParamsDer) ->
    {rsa_pss, rsa_pss_signature_hash(public_key:der_decode('RSASSA-PSS-params', ParamsDer))};
signature_algorithm_metadata(_Other) ->
    throw(invalid_seal_data).

rsa_pss_signature_hash(#'RSASSA-PSS-params'{
                           hashAlgorithm = #'HashAlgorithm'{algorithm = HashAlgorithm},
                           maskGenAlgorithm = #'MaskGenAlgorithm'{
                               algorithm = ?'id-mgf1',
                               parameters = #'HashAlgorithm'{algorithm = HashAlgorithm}
                           },
                           saltLength = SaltLength,
                           trailerField = 1
                       }) ->
    SignatureHash = hash_algorithm_to_atom(HashAlgorithm),
    case SaltLength =:= hash_size(SignatureHash) of
        true -> SignatureHash;
        false -> throw(invalid_seal_data)
    end;
rsa_pss_signature_hash(_Other) ->
    throw(invalid_seal_data).

hash_algorithm_to_atom(?'id-sha256') ->
    sha256;
hash_algorithm_to_atom(?'id-sha384') ->
    sha384;
hash_algorithm_to_atom(?'id-sha512') ->
    sha512;
hash_algorithm_to_atom(_Other) ->
    throw(invalid_seal_data).

cms_signature_digest(SignedContent, EContentType, SignerInfo, SignatureHash) ->
    case SignerInfo#'SignerInfo'.signedAttrs of
        asn1_NOVALUE ->
            crypto:hash(SignatureHash, SignedContent);
        SignedAttrs ->
            SignedAttrsDer = public_key:der_encode('SignedAttributes', SignedAttrs),
            validate_signed_attributes(
                SignedAttrs,
                SignedContent,
                EContentType,
                SignatureHash
            ),
            crypto:hash(SignatureHash, SignedAttrsDer)
    end.

validate_signed_attributes(SignedAttrs, SignedContent, EContentType, SignatureHash) ->
    ExpectedDigest = crypto:hash(SignatureHash, SignedContent),
    case {signed_attribute_value(SignedAttrs, ?'id-contentType'),
          signed_attribute_value(SignedAttrs, ?'id-messageDigest')} of
        {EContentType, ExpectedDigest} ->
            ok;
        _Other ->
            throw(invalid_seal_data)
    end.

signed_attribute_value(SignedAttrs, AttrType) ->
    case [AttrValues || #'Attribute'{
                            type = CurrentAttrType,
                            values = AttrValues
                        } <- SignedAttrs,
                        CurrentAttrType =:= AttrType] of
        [[Value]] -> Value;
        _ -> throw(invalid_seal_data)
    end.

decode_cms_envelope(SignedContent) ->
    case termseal_cbor:decode(SignedContent) of
        {ok, {map, Entries}} ->
            {decode_canonicalization_id(cbor_map_value(
                 Entries,
                 {text, <<"canonicalization_id">>}
             )),
             decode_cms_payload(cbor_map_value(Entries, {text, <<"payload">>}))};
        _Other ->
            throw(invalid_seal_data)
    end.

cbor_map_value(Entries, Key) ->
    case [Value || {CurrentKey, Value} <- Entries, CurrentKey =:= Key] of
        [Value] -> Value;
        _ -> throw(invalid_seal_data)
    end.

decode_canonicalization_id({text, <<"erlang_etf_minor_v2_legacy">>}) ->
    erlang_etf_minor_v2_legacy;
decode_canonicalization_id({text, <<"termseal_cbor_erlang_v1">>}) ->
    termseal_cbor_erlang_v1;
decode_canonicalization_id(_Other) ->
    throw(invalid_seal_data).

decode_cms_payload({bytes, CanonicalForm}) when is_binary(CanonicalForm) ->
    CanonicalForm;
decode_cms_payload(_Other) ->
    throw(invalid_seal_data).

decode_canonical_form(erlang_etf_minor_v2_legacy, CanonicalForm, Opts) ->
    unserialize(CanonicalForm, Opts);
decode_canonical_form(termseal_cbor_erlang_v1, CanonicalForm, _Opts) ->
    case termseal_cbor_erlang:decode(CanonicalForm) of
        {ok, Term} -> Term;
        {error, _Reason} -> throw(invalid_seal_data)
    end.

verify_cms_seal(Parsed, #{unseal_mode := direct_cert,
                          trusted_signer_certs := TrustedSignerCerts} = Opts) ->
    verify_cms_direct_cert(Parsed, TrustedSignerCerts, Opts);
verify_cms_seal(Parsed, #{unseal_mode := trust_anchor,
                          trust_anchors := TrustAnchors} = Opts) ->
    verify_cms_trust_anchor(Parsed, TrustAnchors, Opts);
verify_cms_seal(Parsed, #{unseal_mode := both,
                          trusted_signer_certs := TrustedSignerCerts,
                          trust_anchors := TrustAnchors} = Opts) ->
    verify_cms_direct_cert(Parsed, TrustedSignerCerts, Opts)
        orelse verify_cms_trust_anchor(Parsed, TrustAnchors, Opts).

verify_cms_direct_cert(_Parsed, [], _Opts) ->
    false;
verify_cms_direct_cert(#{signature_request := SignatureRequest,
                         signature := Signature},
                       TrustedSignerCerts,
                       Opts) ->
    lists:any(
        fun(Cert) ->
            cert_is_current_for_direct_verification(Cert, Opts)
                andalso verify_signature(
                    SignatureRequest,
                    Signature,
                    otp_cert_to_der(Cert)
                )
        end,
        TrustedSignerCerts
    ).

verify_cms_trust_anchor(_Parsed, [], _Opts) ->
    false;
verify_cms_trust_anchor(#{signature_request := SignatureRequest,
                          signature := Signature,
                          signer_cert_der := SignerCertDer,
                          chain_ders := ChainDers},
                        TrustAnchors,
                        Opts) ->
    case verify_signature(SignatureRequest, Signature, SignerCertDer) of
        false ->
            false;
        true ->
            CertChain = pkix_cert_chain(SignerCertDer, ChainDers),
            ValidationOptions = pkix_validation_options(Opts),
            lists:any(
                fun(TrustAnchor) ->
                    case public_key:pkix_path_validation(
                             TrustAnchor,
                             CertChain,
                             ValidationOptions
                         ) of
                        {ok, _} -> true;
                        {error, _} -> false
                    end
                end,
                TrustAnchors
            )
    end.

otp_cert_to_der(Cert = #'OTPCertificate'{}) ->
    public_key:pkix_encode('OTPCertificate', Cert, otp).

pkix_cert_chain(SignerCertDer, ChainDers) ->
    pkix_cert_chain_1(SignerCertDer, ChainDers, [SignerCertDer]).

pkix_cert_chain_1(CurrentCertDer, RemainingChainDers, Acc) ->
    CurrentIssuer = cert_issuer(CurrentCertDer),
    case [CandidateCertDer
          || CandidateCertDer <- RemainingChainDers,
             cert_subject(CandidateCertDer) =:= CurrentIssuer] of
        [ParentCertDer] ->
            pkix_cert_chain_1(
                ParentCertDer,
                lists:delete(ParentCertDer, RemainingChainDers),
                [ParentCertDer | Acc]
            );
        _ ->
            Acc
    end.

pkix_validation_options(#{disable_expiration_validation := true}) ->
    [{verify_fun, {fun cms_disable_expiration_verify_fun/3, []}}];
pkix_validation_options(_Opts) ->
    [].

cms_disable_expiration_verify_fun(_Cert, {bad_cert, cert_expired}, UserState) ->
    {valid, UserState};
cms_disable_expiration_verify_fun(_Cert, {bad_cert, Reason}, _UserState) ->
    {fail, {bad_cert, Reason}};
cms_disable_expiration_verify_fun(_Cert, {extension, _Extension}, UserState) ->
    {unknown, UserState};
cms_disable_expiration_verify_fun(_Cert, valid, UserState) ->
    {valid, UserState};
cms_disable_expiration_verify_fun(_Cert, valid_peer, UserState) ->
    {valid, UserState}.

cms_bad_signature_result(#{term := Term}, #{allow_bad_signature := true}) ->
    {bad_signature, Term};
cms_bad_signature_result(_Parsed, _Opts) ->
    throw(bad_signature).

unseal_unsigned(Data, #{allow_unsigned := true} = Opts) ->
    {unsigned, unserialize(Data, Opts)};
unseal_unsigned(_Data, _Opts) ->
    throw(unsigned_seal_not_allowed).

unseal_signed(Data, Sig, Certs, Opts) ->
    AllowBadSig = maps:get(allow_bad_signature, Opts, false),
    case {AllowBadSig, verify_data(Data, Sig, Certs, Opts)} of
        {false, false} -> throw(bad_signature);
        {true, false} -> {bad_signature, unserialize(Data, Opts)};
        {_, true} -> {verified, unserialize(Data, Opts)}
    end.

unserialize(Data, #{safe := true}) -> binary_to_term(Data, [safe]);
unserialize(Data, _Opts) -> binary_to_term(Data, []).

verify_data(_Data, _Sig, [], _Opts) -> false;
verify_data(Data, Sig, [Cert | Rest], Opts) ->
    case cert_is_current_for_direct_verification(Cert, Opts) of
        false ->
            verify_data(Data, Sig, Rest, Opts);
        true ->
            PubKey = cert_to_pubkey(Cert),
            case public_key:verify(Data, ?DEFAULT_SIGHASH, Sig, PubKey) of
                false -> verify_data(Data, Sig, Rest, Opts);
                true -> true
            end
    end.

cert_is_current_for_direct_verification(_Cert,
                                        #{validate_signer_cert_expiration := false}) ->
    true;
cert_is_current_for_direct_verification(Cert,
                                        #{validate_signer_cert_expiration := true}) ->
    cert_is_current(Cert);
cert_is_current_for_direct_verification(_Cert, _Opts) ->
    true.

cert_is_current(#'OTPCertificate'{
                    tbsCertificate = #'OTPTBSCertificate'{
                        validity = #'Validity'{
                            notBefore = NotBefore,
                            notAfter = NotAfter
                        }
                    }
                }) ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    cert_time_to_gregorian_seconds(notBefore, NotBefore) =< Now
        andalso Now =< cert_time_to_gregorian_seconds(notAfter, NotAfter).

cert_time_to_gregorian_seconds(notBefore, {utcTime, [FirstDigitYear | _] = UtcTime}) ->
    Y1 = list_to_integer([FirstDigitYear]),
    YearPrefix =
        case (Y1 > 4 andalso Y1 =< 9) of
            true -> [$1, $9];
            false ->
                {{Year, _Month, _Day}, _Time} = calendar:universal_time(),
                integer_to_list(Year div 100)
        end,
    cert_time_to_gregorian_seconds({generalTime, YearPrefix ++ UtcTime});
cert_time_to_gregorian_seconds(notAfter, {utcTime, UtcTime}) ->
    cert_time_to_gregorian_seconds({generalTime, sliding_year_window(UtcTime)});
cert_time_to_gregorian_seconds(_PeriodOfTime, {generalTime, _Time} = GeneralTime) ->
    cert_time_to_gregorian_seconds(GeneralTime).

cert_time_to_gregorian_seconds({generalTime,
                                [Y1, Y2, Y3, Y4,
                                 M1, M2,
                                 D1, D2,
                                 H1, H2,
                                 Mi1, Mi2,
                                 S1, S2, $Z]}) ->
    Year = list_to_integer([Y1, Y2, Y3, Y4]),
    Month = list_to_integer([M1, M2]),
    Day = list_to_integer([D1, D2]),
    Hour = list_to_integer([H1, H2]),
    Minute = list_to_integer([Mi1, Mi2]),
    Second = list_to_integer([S1, S2]),
    calendar:datetime_to_gregorian_seconds({{Year, Month, Day},
                                            {Hour, Minute, Second}}).

sliding_year_window([Y1, Y2, M1, M2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, Z]) ->
    {{CurrentYear, _, _}, _} = calendar:universal_time(),
    LastTwoDigitYear = CurrentYear rem 100,
    MinYear = ((LastTwoDigitYear - 50) + 100) rem 100,
    YearWindow =
        case list_to_integer([Y1, Y2]) of
            N when N < MinYear -> CurrentYear + 50;
            _N -> CurrentYear - 49
        end,
    [Year1, Year2] = integer_to_list(YearWindow div 100),
    [Year1, Year2, Y1, Y2, M1, M2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, Z].
