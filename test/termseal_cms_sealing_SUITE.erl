%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cms_sealing_SUITE).
-moduledoc """
Common Test contract coverage for the planned CMS sealing path in `termseal`.
""".

%=== INCLUDES ==================================================================

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([local_signer_spec_produces_cms_signed_data/1,
         local_signer_spec_embeds_signer_certificate_and_chain/1,
         local_signer_spec_wraps_payload_with_signed_metadata/1,
         callback_signer_spec_produces_cms_signed_data/1,
         callback_signer_spec_embeds_signer_certificate_and_chain/1,
         callback_signer_receives_canonicalization_metadata/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [local_signer_spec_produces_cms_signed_data,
     local_signer_spec_embeds_signer_certificate_and_chain,
     local_signer_spec_wraps_payload_with_signed_metadata,
     callback_signer_spec_produces_cms_signed_data,
     callback_signer_spec_embeds_signer_certificate_and_chain,
     callback_signer_receives_canonicalization_metadata].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

local_signer_spec_produces_cms_signed_data(Config) ->
    Chain = [intermediate_cert_der(Config)],
    Box = termseal:seal(
        fixture_term(),
        #{
            signer_key => signer_key(Config),
            signer_cert => signer_cert_der(Config),
            chain => Chain,
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    _ = assert_is_cms_signed_data(Box),
    ok.

local_signer_spec_embeds_signer_certificate_and_chain(Config) ->
    SignerCertDer = signer_cert_der(Config),
    Chain = [intermediate_cert_der(Config)],
    Box = termseal:seal(
        fixture_term(),
        #{
            signer_key => signer_key(Config),
            signer_cert => SignerCertDer,
            chain => Chain,
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    {_ContentInfo, SignedData} = assert_is_cms_signed_data(Box),
    EmbeddedCerts = embedded_certificate_ders(SignedData),
    ?assert(lists:member(SignerCertDer, EmbeddedCerts)),
    ?assert(lists:member(hd(Chain), EmbeddedCerts)).

local_signer_spec_wraps_payload_with_signed_metadata(Config) ->
    Box = termseal:seal(
        fixture_term(),
        #{
            signer_key => signer_key(Config),
            signer_cert => signer_cert_der(Config),
            chain => [intermediate_cert_der(Config)],
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    {_ContentInfo, SignedData} = assert_is_cms_signed_data(Box),
    EncapsulatedContent = encapsulated_content(SignedData),
    CanonicalPayload = termseal:signing_payload(fixture_term()),
    ?assertNotEqual(asn1_NOVALUE, EncapsulatedContent),
    ?assertNotEqual(CanonicalPayload, EncapsulatedContent).

callback_signer_spec_produces_cms_signed_data(Config) ->
    Key = signer_key(Config),
    CertDer = signer_cert_der(Config),
    Chain = [intermediate_cert_der(Config)],
    SignerFun = fun(Request) ->
        #{
            signature => sign_request_digest(Request, Key),
            signer_cert => CertDer,
            chain => Chain
        }
    end,
    Box = termseal:seal(
        fixture_term(),
        #{
            signer_fun => SignerFun,
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    _ = assert_is_cms_signed_data(Box),
    ok.

callback_signer_spec_embeds_signer_certificate_and_chain(Config) ->
    Key = signer_key(Config),
    SignerCertDer = signer_cert_der(Config),
    Chain = [intermediate_cert_der(Config)],
    SignerFun = fun(Request) ->
        #{
            signature => sign_request_digest(Request, Key),
            signer_cert => SignerCertDer,
            chain => Chain
        }
    end,
    Box = termseal:seal(
        fixture_term(),
        #{
            signer_fun => SignerFun,
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    {_ContentInfo, SignedData} = assert_is_cms_signed_data(Box),
    EmbeddedCerts = embedded_certificate_ders(SignedData),
    ?assert(lists:member(SignerCertDer, EmbeddedCerts)),
    ?assert(lists:member(hd(Chain), EmbeddedCerts)).

callback_signer_receives_canonicalization_metadata(Config) ->
    Parent = self(),
    Key = signer_key(Config),
    CertDer = signer_cert_der(Config),
    Chain = [intermediate_cert_der(Config)],
    SignerFun = fun(Request) ->
        Parent ! {signer_request, Request},
        #{
            signature => sign_request_digest(Request, Key),
            signer_cert => CertDer,
            chain => Chain
        }
    end,
    _ = termseal:seal(
        fixture_term(),
        #{
            signer_fun => SignerFun,
            signature_hash => sha256,
            signature_scheme => direct_signature
        }
    ),
    ExpectedPayload = termseal:signing_payload(fixture_term()),
    ExpectedDigest = crypto:hash(sha256, ExpectedPayload),
    ExpectedRequest = #{
        canonicalization_id => termseal_cbor_erlang_v1,
        payload => ExpectedPayload,
        payload_digest => ExpectedDigest,
        signing_digest => ExpectedDigest,
        signing_subject => payload,
        signature_hash => sha256,
        signature_scheme => direct_signature
    },
    receive
        {signer_request, Request} ->
            ?assertEqual(ExpectedRequest, Request)
    after 1000 ->
        ct:fail(signer_request_not_received)
    end.


%=== INTERNAL FUNCTIONS ========================================================

fixture_term() ->
    {1, a, #{foo => "bar", buz => 42}, [-1]}.

signer_key(Config) ->
    termseal:load_private_key(fixture_path(Config, ["keys", "cms_signer.key"])).

signer_cert_der(Config) ->
    [Entry] = [Der || {'Certificate', Der, not_encrypted} <- pem_entries(Config, ["certs", "cms_signer.crt"])],
    Entry.

intermediate_cert_der(Config) ->
    [Entry] = [Der || {'Certificate', Der, not_encrypted} <- pem_entries(Config, ["certs", "cms_intermediate_ca.crt"])],
    Entry.

sign_request_digest(Request, Key) ->
    public_key:sign({digest, maps:get(signing_digest, Request)},
                    maps:get(signature_hash, Request),
                    Key).

assert_is_cms_content_info(Box) when is_binary(Box) ->
    case Box of
        <<"TSF", _/binary>> ->
            ct:fail({expected_cms_content_info, got_tsf_v1_box});
        _ ->
            ok
    end,
    case catch public_key:der_decode('ContentInfo', Box) of
        {'EXIT', Reason} ->
            ct:fail({invalid_cms_content_info, Reason});
        ContentInfo ->
            ContentInfo
    end.

assert_is_cms_signed_data(Box) ->
    ContentInfo = assert_is_cms_content_info(Box),
    ?assertMatch(#'ContentInfo'{contentType = ?'id-signedData'}, ContentInfo),
    #'ContentInfo'{content = SignedData} = ContentInfo,
    ?assertMatch(#'SignedData'{}, SignedData),
    {ContentInfo, SignedData}.

embedded_certificate_ders(#'SignedData'{certificates = Certificates}) when is_list(Certificates) ->
    [public_key:der_encode('Certificate', Cert)
     || {certificate, Cert} <- Certificates];
embedded_certificate_ders(#'SignedData'{certificates = asn1_NOVALUE}) ->
    [].

encapsulated_content(#'SignedData'{
                        encapContentInfo =
                            #'EncapsulatedContentInfo'{eContent = Content}
                    }) ->
    Content.

pem_entries(Config, RelativePath) ->
    public_key:pem_decode(read_binary_file(Config, RelativePath)).

read_binary_file(Config, RelativePath) ->
    Path = fixture_path(Config, RelativePath),
    case file:read_file(Path) of
        {ok, Data} -> Data;
        {error, Reason} -> ct:fail({fixture_read_error, Reason, Path})
    end.

fixture_path(Config, RelativePath) ->
    filename:join([?config(data_dir, Config) | RelativePath]).
