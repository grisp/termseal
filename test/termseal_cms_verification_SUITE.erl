%% SPDX-FileCopyrightText: 2026 Stritzinger GmbH <peer@stritzinger.com>
%% SPDX-License-Identifier: Apache-2.0

-module(termseal_cms_verification_SUITE).
-moduledoc """
Common Test contract coverage for the planned CMS verification path in `termseal`.
""".

%=== INCLUDES ==================================================================

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


%=== EXPORTS ===================================================================

% Common Test callbacks
-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
% Test cases
-export([trust_anchor_verifies_valid_cms_chain/1,
         direct_cert_verifies_with_trusted_signer_certificate/1,
         direct_cert_accepts_expired_signer_without_validation/1,
         direct_cert_rejects_expired_signer_when_validation_enabled/1,
         positional_root_certificate_does_not_act_as_trust_anchor/1,
         wrong_trust_anchor_is_rejected/1,
         missing_intermediate_chain_is_rejected/1,
         wrong_embedded_chain_is_rejected/1,
         trust_anchor_verifies_unordered_embedded_chain_with_root/1,
         trust_anchor_verifies_with_extra_unrelated_embedded_certificate/1,
         both_mode_accepts_when_direct_cert_matches/1,
         both_mode_accepts_when_trust_anchor_matches/1,
         both_mode_rejects_when_both_paths_fail/1,
         conflicting_trusted_signer_cert_inputs_are_rejected/1,
         disable_expiration_validation_accepts_expired_chains/1,
         expired_leaf_certificate_is_rejected/1,
         expired_intermediate_certificate_is_rejected/1,
         expired_root_certificate_is_rejected/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [trust_anchor_verifies_valid_cms_chain,
     direct_cert_verifies_with_trusted_signer_certificate,
     direct_cert_accepts_expired_signer_without_validation,
     direct_cert_rejects_expired_signer_when_validation_enabled,
     positional_root_certificate_does_not_act_as_trust_anchor,
     wrong_trust_anchor_is_rejected,
     missing_intermediate_chain_is_rejected,
     wrong_embedded_chain_is_rejected,
     trust_anchor_verifies_unordered_embedded_chain_with_root,
     trust_anchor_verifies_with_extra_unrelated_embedded_certificate,
     both_mode_accepts_when_direct_cert_matches,
     both_mode_accepts_when_trust_anchor_matches,
     both_mode_rejects_when_both_paths_fail,
     conflicting_trusted_signer_cert_inputs_are_rejected,
     disable_expiration_validation_accepts_expired_chains,
     expired_leaf_certificate_is_rejected,
     expired_intermediate_certificate_is_rejected,
     expired_root_certificate_is_rejected].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.


%=== TEST FUNCTIONS ============================================================

trust_anchor_verifies_valid_cms_chain(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, [], Opts)).

direct_cert_verifies_with_trusted_signer_certificate(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    ?assertEqual(
        {verified, fixture_term()},
        termseal:unseal(Box, valid_signer_certs(Config), #{})
    ).

direct_cert_accepts_expired_signer_without_validation(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_expired_leaf_signed.base64"),
    ?assertEqual(
        {verified, fixture_term()},
        termseal:unseal(Box, expired_leaf_signer_certs(Config), #{})
    ).

direct_cert_rejects_expired_signer_when_validation_enabled(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_expired_leaf_signed.base64"),
    ?assertThrow(
        bad_signature,
        termseal:unseal(
            Box,
            expired_leaf_signer_certs(Config),
            #{validate_signer_cert_expiration => true}
        )
    ).

positional_root_certificate_does_not_act_as_trust_anchor(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    ?assertThrow(bad_signature, termseal:unseal(Box, valid_root_certs(Config), #{})).

wrong_trust_anchor_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    Opts = #{
        trust_anchors => unrelated_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).

missing_intermediate_chain_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_missing_intermediate_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).

wrong_embedded_chain_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_wrong_chain_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).

trust_anchor_verifies_unordered_embedded_chain_with_root(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_unordered_chain_with_root_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, [], Opts)).

trust_anchor_verifies_with_extra_unrelated_embedded_certificate(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_extra_unrelated_cert_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, [], Opts)).

both_mode_accepts_when_direct_cert_matches(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    Opts = #{
        trust_anchors => unrelated_root_certs(Config)
    },
    ?assertEqual(
        {verified, fixture_term()},
        termseal:unseal(Box, valid_signer_certs(Config), Opts)
    ).

both_mode_accepts_when_trust_anchor_matches(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    Opts = #{
        trust_anchors => valid_root_certs(Config)
    },
    ?assertEqual(
        {verified, fixture_term()},
        termseal:unseal(Box, unrelated_signer_certs(Config), Opts)
    ).

both_mode_rejects_when_both_paths_fail(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    Opts = #{
        trust_anchors => unrelated_root_certs(Config)
    },
    ?assertThrow(
        bad_signature,
        termseal:unseal(Box, unrelated_signer_certs(Config), Opts)
    ).

conflicting_trusted_signer_cert_inputs_are_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_valid_signed.base64"),
    SignerCerts = valid_signer_certs(Config),
    ?assertThrow(
        conflicting_trusted_signer_certs,
        termseal:unseal(
            Box,
            SignerCerts,
            #{trusted_signer_certs => SignerCerts}
        )
    ).

disable_expiration_validation_accepts_expired_chains(Config) ->
    assert_expired_chain_is_accepted(
        Config,
        "fixture_cms_expired_leaf_signed.base64",
        expired_leaf_root_certs(Config)
    ),
    assert_expired_chain_is_accepted(
        Config,
        "fixture_cms_expired_intermediate_signed.base64",
        expired_intermediate_root_certs(Config)
    ),
    assert_expired_chain_is_accepted(
        Config,
        "fixture_cms_expired_root_signed.base64",
        expired_root_root_certs(Config)
    ).

expired_leaf_certificate_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_expired_leaf_signed.base64"),
    Opts = #{
        trust_anchors => expired_leaf_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).

expired_intermediate_certificate_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_expired_intermediate_signed.base64"),
    Opts = #{
        trust_anchors => expired_intermediate_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).

expired_root_certificate_is_rejected(Config) ->
    Box = load_seal_fixture(Config, "fixture_cms_expired_root_signed.base64"),
    Opts = #{
        trust_anchors => expired_root_root_certs(Config),
        unseal_mode => trust_anchor
    },
    ?assertThrow(bad_signature, termseal:unseal(Box, [], Opts)).


%=== INTERNAL FUNCTIONS ========================================================

fixture_term() ->
    {1, a, #{foo => "bar", buz => 42}, [-1]}.

valid_root_certs(Config) ->
    load_certs(Config, "valid_cms_root_ca.crt").

valid_signer_certs(Config) ->
    load_certs(Config, "valid_cms_signer.crt").

unrelated_root_certs(Config) ->
    load_certs(Config, "unrelated_cms_root_ca.crt").

unrelated_signer_certs(Config) ->
    load_certs(Config, "unrelated_cms_signer.crt").

expired_leaf_root_certs(Config) ->
    load_certs(Config, "expired_leaf_cms_root_ca.crt").

expired_leaf_signer_certs(Config) ->
    load_certs(Config, "expired_leaf_cms_signer.crt").

expired_intermediate_root_certs(Config) ->
    load_certs(Config, "expired_intermediate_cms_root_ca.crt").

expired_root_root_certs(Config) ->
    load_certs(Config, "expired_root_cms_root_ca.crt").

load_certs(Config, Filename) ->
    termseal:load_certificates(fixture_path(Config, ["certs", Filename])).

load_seal_fixture(Config, Filename) ->
    Encoded = read_binary_file(Config, ["seals", Filename]),
    base64:decode(binary:replace(Encoded, <<"\n">>, <<>>, [global])).

assert_expired_chain_is_accepted(Config, SealFixture, TrustAnchors) ->
    Box = load_seal_fixture(Config, SealFixture),
    Opts = #{
        trust_anchors => TrustAnchors,
        unseal_mode => trust_anchor,
        disable_expiration_validation => true
    },
    ?assertEqual({verified, fixture_term()}, termseal:unseal(Box, [], Opts)).

read_binary_file(Config, RelativePath) ->
    Path = fixture_path(Config, RelativePath),
    case file:read_file(Path) of
        {ok, Data} -> Data;
        {error, Reason} -> ct:fail({fixture_read_error, Reason, Path})
    end.

fixture_path(Config, RelativePath) ->
    filename:join([?config(data_dir, Config) | RelativePath]).
