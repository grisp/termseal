-module(termseal_tsf_v1_SUITE).

%=== INCLUDES ==================================================================

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([unsigned_fixture_roundtrip/1,
         seal_with_undefined_key_matches_unsigned_fixture/1,
         canonical_payload_matches_term_to_binary_minor_v2/1,
         rsa_fixture_roundtrip/1,
         ec_fixture_roundtrip/1,
         expired_signer_certificate_is_accepted_by_default/1,
         validate_signer_cert_expiration_rejects_expired_signer_certificate/1,
         generated_signed_boxes_roundtrip/1,
         multicert_verification/1,
         bad_signature_behavior/1,
         unsupported_version/1,
         malformed_seal_format/1,
         invalid_seal_data/1,
         load_private_key_missing_file/1,
         load_private_key_rejects_files_without_keys/1,
         load_private_key_rejects_multiple_keys/1,
         load_certificates_ignores_non_certificate_entries/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [unsigned_fixture_roundtrip,
     seal_with_undefined_key_matches_unsigned_fixture,
     canonical_payload_matches_term_to_binary_minor_v2,
     rsa_fixture_roundtrip,
     ec_fixture_roundtrip,
     expired_signer_certificate_is_accepted_by_default,
     validate_signer_cert_expiration_rejects_expired_signer_certificate,
     generated_signed_boxes_roundtrip,
     multicert_verification,
     bad_signature_behavior,
     unsupported_version,
     malformed_seal_format,
     invalid_seal_data,
     load_private_key_missing_file,
     load_private_key_rejects_files_without_keys,
     load_private_key_rejects_multiple_keys,
     load_certificates_ignores_non_certificate_entries].


init_per_suite(Config) ->
    Config.


end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

unsigned_fixture_roundtrip(_Config) ->
    Box = load_fixture(_Config, ["seals", "fixture_tsf_v1_unsigned.base64"]),
    ?assertThrow(unsigned_seal_not_allowed, termseal:unseal(Box, [])),
    ?assertEqual({unsigned, fixture_term()},
                 termseal:unseal(Box, [], #{allow_unsigned => true})).


seal_with_undefined_key_matches_unsigned_fixture(_Config) ->
    ?assertEqual(unsigned_box(), termseal:seal(fixture_term(), undefined)).


canonical_payload_matches_term_to_binary_minor_v2(_Config) ->
    ExpectedPayload = term_to_binary(fixture_term(), [{minor_version, 2}]),
    UnsignedPayload = payload_from_unsigned_box(unsigned_box()),
    SignedPayload = payload_from_signed_box(rsa_box(_Config)),
    ?assertEqual(ExpectedPayload, UnsignedPayload),
    ?assertEqual(ExpectedPayload, SignedPayload),
    ok.


rsa_fixture_roundtrip(Config) ->
    Box = load_fixture(Config, ["seals", "fixture_tsf_v1_rsa_signed.base64"]),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, rsa_certs(Config))),
    ?assertThrow(bad_signature, termseal:unseal(Box, ec_certs(Config))),
    ?assertThrow(bad_signature, termseal:unseal(Box, [])).


ec_fixture_roundtrip(Config) ->
    Box = load_fixture(Config, ["seals", "fixture_tsf_v1_ec_signed.base64"]),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, ec_certs(Config))),
    ?assertThrow(bad_signature, termseal:unseal(Box, rsa_certs(Config))),
    ?assertThrow(bad_signature, termseal:unseal(Box, [])).

expired_signer_certificate_is_accepted_by_default(Config) ->
    Box = load_fixture(Config, ["seals", "fixture_tsf_v1_rsa_signed.base64"]),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, expired_rsa_certs(Config))).

validate_signer_cert_expiration_rejects_expired_signer_certificate(Config) ->
    Box = load_fixture(Config, ["seals", "fixture_tsf_v1_rsa_signed.base64"]),
    ?assertThrow(
        bad_signature,
        termseal:unseal(
            Box,
            expired_rsa_certs(Config),
            #{validate_signer_cert_expiration => true}
        )
    ).


generated_signed_boxes_roundtrip(Config) ->
    ?assertEqual({verified, fixture_term()}, termseal:unseal(rsa_box(Config), rsa_certs(Config))),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(ec_box(Config), ec_certs(Config))).


multicert_verification(Config) ->
    Certs = rsa_certs(Config) ++ ec_certs(Config),
    RsaBox = load_fixture(Config, ["seals", "fixture_tsf_v1_rsa_signed.base64"]),
    EcBox = load_fixture(Config, ["seals", "fixture_tsf_v1_ec_signed.base64"]),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(RsaBox, Certs)),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(RsaBox, lists:reverse(Certs))),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(EcBox, Certs)),
    ?assertEqual({verified, fixture_term()}, termseal:unseal(EcBox, lists:reverse(Certs))).


bad_signature_behavior(Config) ->
    Box = tamper_signature(load_fixture(Config, ["seals", "fixture_tsf_v1_rsa_signed.base64"])),
    ?assertThrow(bad_signature, termseal:unseal(Box, rsa_certs(Config))),
    ?assertEqual({bad_signature, fixture_term()},
                 termseal:unseal(Box, rsa_certs(Config), #{allow_bad_signature => true})).


unsupported_version(Config) ->
    <<Magic:3/binary, _Version:16/unsigned-big-integer, Rest/binary>> =
        load_fixture(Config, ["seals", "fixture_tsf_v1_unsigned.base64"]),
    Box = <<Magic/binary, 2:16/unsigned-big-integer, Rest/binary>>,
    ?assertThrow({usupported_seal_version, 2}, termseal:unseal(Box, [])).


malformed_seal_format(_Config) ->
    Box = <<"TSF", 1:16/unsigned-big-integer, 0:1, 0:15, 3:32/unsigned-big-integer, 1, 2>>,
    ?assertThrow(bad_seal_format, termseal:unseal(Box, [])).


invalid_seal_data(_Config) ->
    ?assertThrow(invalid_seal_data, termseal:unseal(<<"NOTTSF">>, [])).


load_private_key_missing_file(Config) ->
    Filename = fixture_path(Config, ["keys", "missing-do-not-create.key"]),
    ?assertThrow({read_error, enoent, Filename}, termseal:load_private_key(Filename)).


load_private_key_rejects_files_without_keys(Config) ->
    Filename = fixture_path(Config, ["certs", "CA_rsa.crt"]),
    ?assertThrow({key_not_found, Filename}, termseal:load_private_key(Filename)).


load_private_key_rejects_multiple_keys(Config) ->
    Filename = fixture_path(Config, ["keys", "two_keys.pem"]),
    ?assertThrow({too_many_keys, Filename}, termseal:load_private_key(Filename)).


load_certificates_ignores_non_certificate_entries(Config) ->
    ?assertEqual([], termseal:load_certificates(fixture_path(Config, ["keys", "CA_rsa.key"]))),
    ?assertEqual([], termseal:load_certificates(fixture_path(Config, ["keys", "two_keys.pem"]))).


%=== INTERNAL FUNCTIONS ========================================================

fixture_term() ->
    {1, a, #{foo => "bar", buz => 42}, [-1]}.


rsa_key(Config) ->
    termseal:load_private_key(fixture_path(Config, ["keys", "CA_rsa.key"])).


ec_key(Config) ->
    termseal:load_private_key(fixture_path(Config, ["keys", "CA_ec.key"])).


rsa_certs(Config) ->
    termseal:load_certificates(fixture_path(Config, ["certs", "CA_rsa.crt"])).

expired_rsa_certs(Config) ->
    termseal:load_certificates(fixture_path(Config, ["certs", "expired_CA_rsa.crt"])).


ec_certs(Config) ->
    termseal:load_certificates(fixture_path(Config, ["certs", "CA_ec.crt"])).


unsigned_box() ->
    termseal:seal(fixture_term()).


rsa_box(Config) ->
    termseal:seal(fixture_term(), rsa_key(Config)).


ec_box(Config) ->
    termseal:seal(fixture_term(), ec_key(Config)).


payload_from_unsigned_box(<<$T, $S, $F,
                            1:16/unsigned-big-integer,
                            0:1, _:15,
                            DataLen:32/unsigned-big-integer,
                            Data:DataLen/binary>>) ->
    Data.


payload_from_signed_box(<<$T, $S, $F,
                          1:16/unsigned-big-integer,
                          1:1, _:15,
                          SigLen:32/unsigned-big-integer,
                          _Sig:SigLen/binary,
                          DataLen:32/unsigned-big-integer,
                          Data:DataLen/binary>>) ->
    Data.


load_fixture(Config, RelativePath) ->
    Encoded = read_binary_file(Config, RelativePath),
    base64:decode(binary:replace(Encoded, <<"\n">>, <<>>, [global])).


read_binary_file(Config, RelativePath) ->
    Path = fixture_path(Config, RelativePath),
    case file:read_file(Path) of
        {ok, Data} -> Data;
        {error, Reason} -> ct:fail({fixture_read_error, Reason, Path})
    end.


tamper_signature(<<$T, $S, $F,
                   1:16/unsigned-big-integer,
                   1:1, Reserved:15,
                   SigLen:32/unsigned-big-integer,
                   Sig:SigLen/binary,
                   Rest/binary>>) ->
    <<Head, Tail/binary>> = Sig,
    TamperedSig = <<(Head bxor 16#01), Tail/binary>>,
    <<"TSF",
      1:16/unsigned-big-integer,
      1:1, Reserved:15,
      SigLen:32/unsigned-big-integer,
      TamperedSig/binary,
      Rest/binary>>.


fixture_path(Config, RelativePath) ->
    filename:join([?config(data_dir, Config) | RelativePath]).
