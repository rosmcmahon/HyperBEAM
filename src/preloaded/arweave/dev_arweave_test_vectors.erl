%%% @doc Test vectors for the Arweave codecs, `tx@1.0' and `ans104@1.0'.
-module(dev_arweave_test_vectors).
-include_lib("eunit/include/eunit.hrl").
-include("include/hb.hrl").

%% @doc Options for each test: a new store and the node's wallet.
test_opts() ->
    #{
        <<"store">> => hb_test_utils:test_store(),
        <<"priv-wallet">> => hb:wallet()
    }.

%% @doc Commitment identities belong to the signature or unsigned digest.
commitment_identity_test_() ->
    [
        {binary_to_list(Codec) ++ ": " ++ atom_to_list(Kind), fun() ->
            Opts = test_opts(),
            Msg = case Kind of
                signed ->
                    hb_message:commit(
                        #{ <<"body">> => <<"original">> }, Opts, Codec);
                unsigned ->
                    hb_message:convert(
                        ar_tx:normalize(#tx{
                            format = Format,
                            tags = [{<<"Example-Key">>, <<"value">>}],
                            data = <<"original">>
                        }),
                        <<"structured@1.0">>, Codec, Opts
                    )
            end,
            Verify = fun(M) ->
                hb_message:verify(M,
                    #{ <<"ids">> => <<"all">> }, Opts)
            end,
            [{ID, Commitment}] = maps:to_list(maps:get(<<"commitments">>, Msg)),
            FalseID = hb_util:human_id(<<0:256>>),
            ?assert(Verify(Msg)),
            ?assertNot(Verify(Msg#{ <<"commitments">> =>
                #{ FalseID => Commitment } })),
            ?assertNot(Verify(Msg#{ <<"commitments">> =>
                #{ ID => Commitment#{ <<"committer">> => FalseID } } }))
        end}
    || {Codec, Format} <- [{<<"ans104@1.0">>, ans104}, {<<"tx@1.0">>, 2}],
        Kind <- [signed, unsigned]
    ].

rsa_wallet_not_match_message_ed25519_type_test() ->
    Opts = #{<<"priv-wallet">> => ar_wallet:new(?RSA_KEY_TYPE)},
    SignatureType = ?EDDSA_SIGN_TYPE,
    Msg = #{<<"a">> => <<"b">>},
    ?assertThrow({wrong_wallet_to_sign,
                 {request_type, ?EDDSA_SIGN_TYPE},
                 {wallet_type, {rsa,65537}}},
        hb_message:commit(
            Msg,
            Opts,
            #{<<"commitment-device">> => <<"ans104@1.0">>, <<"type">> => SignatureType}
        )).

ed25519_wallet_not_match_message_rsa_type_test() ->
    Opts = #{<<"priv-wallet">> => ar_wallet:new(?EDDSA_KEY_TYPE)},
    SignatureType = ?RSA_SIGN_TYPE,
    Msg = #{<<"a">> => <<"b">>},
    ?assertThrow({wrong_wallet_to_sign,
                 {request_type, ?RSA_SIGN_TYPE},
                 {wallet_type, {eddsa,ed25519}}},
        hb_message:commit(
            Msg,
            Opts,
            #{<<"commitment-device">> => <<"ans104@1.0">>, <<"type">> => SignatureType}
        )).

ethereum_wallet_not_match_message_rsa_type_test() ->
    Opts = #{<<"priv-wallet">> => ar_wallet:new(?ETHEREUM_KEY_TYPE)},
    SignatureType = ?RSA_SIGN_TYPE,
    Msg = #{<<"a">> => <<"b">>},
    ?assertThrow({wrong_wallet_to_sign,
                 {request_type, ?RSA_SIGN_TYPE},
                 {wallet_type, ethereum}},
        hb_message:commit(
            Msg,
            Opts,
            #{<<"commitment-device">> => <<"ans104@1.0">>, <<"type">> => SignatureType}
        )).

ethereum_wallet_match_message_ethereum_type_test() ->
    Opts = #{<<"priv-wallet">> => ar_wallet:new(?ETHEREUM_KEY_TYPE)},
    SignatureType = <<"ethereum">>,
    Msg = #{<<"a">> => <<"b">>},
    ?assert(is_map(hb_message:commit(
            Msg,
            Opts,
            #{<<"commitment-device">> => <<"ans104@1.0">>, <<"type">> => SignatureType}
        ))).
