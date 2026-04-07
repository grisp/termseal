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
         wrong_trust_anchor_is_rejected/1,
         missing_intermediate_chain_is_rejected/1,
         wrong_embedded_chain_is_rejected/1,
         expired_leaf_certificate_is_rejected/1,
         expired_intermediate_certificate_is_rejected/1,
         expired_root_certificate_is_rejected/1]).


%=== COMMON TEST CALLBACKS =====================================================

all() ->
    [trust_anchor_verifies_valid_cms_chain,
     wrong_trust_anchor_is_rejected,
     missing_intermediate_chain_is_rejected,
     wrong_embedded_chain_is_rejected,
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

unrelated_root_certs(Config) ->
    load_certs(Config, "unrelated_cms_root_ca.crt").

expired_leaf_root_certs(Config) ->
    load_certs(Config, "expired_leaf_cms_root_ca.crt").

expired_intermediate_root_certs(Config) ->
    load_certs(Config, "expired_intermediate_cms_root_ca.crt").

expired_root_root_certs(Config) ->
    load_certs(Config, "expired_root_cms_root_ca.crt").

load_certs(Config, Filename) ->
    termseal:load_certificates(fixture_path(Config, ["certs", Filename])).

load_seal_fixture(Config, Filename) ->
    Encoded = read_binary_file(Config, ["seals", Filename]),
    base64:decode(binary:replace(Encoded, <<"\n">>, <<>>, [global])).

read_binary_file(Config, RelativePath) ->
    Path = fixture_path(Config, RelativePath),
    case file:read_file(Path) of
        {ok, Data} -> Data;
        {error, Reason} -> ct:fail({fixture_read_error, Reason, Path})
    end.

fixture_path(Config, RelativePath) ->
    filename:join([?config(data_dir, Config) | RelativePath]).
