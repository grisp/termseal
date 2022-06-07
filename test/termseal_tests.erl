-module(termseal_tests).


%--- Incudes -------------------------------------------------------------------

-include_lib("eunit/include/eunit.hrl").


%--- Test Suites ---------------------------------------------------------------

seal_unseal_ec_test() ->
    Key = termseal:load_private_key(test_file_path("CA_ec.key")),
    GoodCerts = termseal:load_certificates(test_file_path("CA_ec.crt")),
    BadCerts = termseal:load_certificates(test_file_path("CA_rsa.crt")),
    Term = {1, a, #{foo => "bar", buz => 42}, [-1]},
    Box = termseal:seal(Term, Key),
    ?assertEqual({verified, Term}, termseal:unseal(Box, GoodCerts)),
    ?assertThrow(bad_signature, termseal:unseal(Box, BadCerts)),
    ?assertThrow(bad_signature, termseal:unseal(Box, [])),
    ok.

seal_unseal_rsa_test() ->
    Key = termseal:load_private_key(test_file_path("CA_rsa.key")),
    GoodCerts = termseal:load_certificates(test_file_path("CA_rsa.crt")),
    BadCerts = termseal:load_certificates(test_file_path("CA_ec.crt")),
    Term = {1, a, #{foo => "bar", buz => 42}, [-1]},
    Box = termseal:seal(Term, Key),
    ?assertEqual({verified, Term}, termseal:unseal(Box, GoodCerts)),
    ?assertThrow(bad_signature, termseal:unseal(Box, BadCerts)),
    ?assertThrow(bad_signature, termseal:unseal(Box, [])),
    ok.

seal_unseal_multicert_test() ->
    Key1 = termseal:load_private_key(test_file_path("CA_rsa.key")),
    Key2 = termseal:load_private_key(test_file_path("CA_ec.key")),
    Certs1 = termseal:load_certificates(test_file_path("CA_rsa.crt")),
    Certs2 = termseal:load_certificates(test_file_path("CA_ec.crt")),
    Term = {1, a, #{foo => "bar", buz => 42}, [-1]},
    Box1 = termseal:seal(Term, Key1),
    ?assertEqual({verified, Term}, termseal:unseal(Box1, Certs1 ++ Certs2)),
    ?assertEqual({verified, Term}, termseal:unseal(Box1, Certs2 ++ Certs1)),
    Box2 = termseal:seal(Term, Key2),
    ?assertEqual({verified, Term}, termseal:unseal(Box2, Certs1 ++ Certs2)),
    ?assertEqual({verified, Term}, termseal:unseal(Box2, Certs2 ++ Certs1)),
    ok.

seal_unseal_unsigned_test() ->
    Term = {1, a, #{foo => "bar", buz => 42}, [-1]},
    Box = termseal:seal(Term),
    ?assertThrow(unsigned_seal_not_allowed, termseal:unseal(Box, [])),
    ?assertEqual({unsigned, Term}, termseal:unseal(Box, [], #{allow_unsigned => true})),
    ok.


%--- Internal Functions --------------------------------------------------------

test_file_path(SubPath) ->
    {ok, Pwd} = file:get_cwd(),
    filename:join([Pwd, "test", SubPath]).
