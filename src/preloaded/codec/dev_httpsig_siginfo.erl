%% @doc A module for converting between commitments and their encoded `signature'
%% and `signature-input' keys.
-module(dev_httpsig_siginfo).
-export([commitments_to_siginfo/3, siginfo_to_commitments/3]).
-export([committed_keys_to_siginfo/1, to_siginfo_keys/3, from_siginfo_keys/3]).
-export([add_derived_specifiers/1, remove_derived_specifiers/1]).
-export([commitment_to_sig_name/1, derived_commitment_id/1]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%%% A list of components that are `derived' in the context of RFC-9421 from the
%%% request message.
-define(DERIVED_COMPONENTS, [
    <<"method">>,
    <<"target-uri">>,
    <<"authority">>,
    <<"scheme">>,
    <<"request-target">>,
    <<"path">>,
    <<"query">>,
    <<"query-param">>
    % <<"status">> % Some libraries do not support it
]).

%% @doc Generate a `signature' and `signature-input' key pair from a commitment
%% map.
commitments_to_siginfo(_Msg, Comms, _Opts) when ?IS_EMPTY_MESSAGE(Comms) ->
    #{};
commitments_to_siginfo(Msg, Comms, Opts) ->
    % Emit a SF item per commitment. `CommID' is threaded through so
    % `commitment_to_sf_siginfo/4' can add an `id' parameter whenever the
    % decoder-side derivation would not reproduce the sender's map key.
    {Sigs, SigInputs} =
        maps:fold(
            fun(CommID, Commitment, {Sigs, SigInputs}) ->
                {ok, SigNameRaw, SFSig, SFSigInput} =
                    commitment_to_sf_siginfo(Msg, CommID, Commitment, Opts),
                SigName = <<"comm-", SigNameRaw/binary>>,
                {
                    Sigs#{ SigName => SFSig },
                    SigInputs#{ SigName => SFSigInput }
                }
            end,
            {#{}, #{}},
            Comms
        ),
    #{
        <<"signature">> =>
            hb_util:bin(hb_structured_fields:dictionary(Sigs)),
        <<"signature-input">> =>
            hb_util:bin(hb_structured_fields:dictionary(SigInputs))
    }.

%% @doc Generate a `signature' and `signature-input' key pair from a given
%% commitment.
commitment_to_sf_siginfo(Msg, CommID, Commitment, Opts) ->
    % Generate the `alg' key from the commitment.
    Alg = commitment_to_alg(Commitment, Opts),
    % Find the public key from the commitment, which we will use as the
    % `keyid' in the `signature-input' keys. Absent in the commitment =>
    % absent on the wire (permitted by RFC 9421 §1.4.2.3).
    KeyID = maps:get(<<"keyid">>, Commitment, undefined),
    % Extract the signature from the commitment.
    Signature = hb_util:decode(maps:get(<<"signature">>, Commitment)),
    % Extract the keys present in the commitment.
    CommittedKeys = to_siginfo_keys(Msg, Commitment, Opts),
    ?event_debug({normalized_for_enc, CommittedKeys, {commitment, Commitment}}),
    % Extract the hashpath, used as a tag, from the commitment.
    Tag = maps:get(<<"tag">>, Commitment, undefined),
    % Extract other permissible values, if present.
    Nonce = maps:get(<<"nonce">>, Commitment, undefined),
    Created = maps:get(<<"created">>, Commitment, undefined),
    Expires = maps:get(<<"expires">>, Commitment, undefined),
    % Generate the name of the signature.
    SigName = hb_util:to_lower(hb_util:human_id(crypto:hash(sha256, Signature))),
    % If the decoder's derivation would not reproduce the sender's map key,
    % transport it explicitly as an `id' parameter. Content-addressed devices
    % (e.g. `~ipfs@1.0') key on a CID that is not a function of `Sig'; HMAC,
    % RSA-PSS, and other `h(Sig)'-keyed devices never pay this cost.
    DerivedID = derived_commitment_id(Signature),
    IDParam =
        case CommID of
            undefined -> [];
            DerivedID -> [];
            _         -> [{<<"id">>, {string, CommID}}]
        end,
    % Generate the signature input and signature structured-fields. These can
    % then be placed into a dictionary with other commitments and transformed
    % into their binary representations.
    SFSig = {item, {binary, Signature}, []},
    AdditionalParams = get_additional_params(Commitment),
    KeyIDItem =
        case KeyID of
            undefined -> undefined;
            _         -> {string, KeyID}
        end,
    Params =
        lists:filter(
            fun({_Key, undefined}) ->
                false;
               ({_Key, {_, Val}}) ->
                Val =/= undefined
            end,
            [
                {<<"alg">>, {string, Alg}},
                {<<"keyid">>, KeyIDItem},
                {<<"tag">>, {string, Tag}},
                {<<"created">>, Created},
                {<<"expires">>, Expires},
                {<<"nonce">>, {string, Nonce}}
            ] ++ IDParam ++ AdditionalParams
        ),
    SFSigInput =
        {list,
            [
                {item, {string, Key}, []}
            ||
                Key <- CommittedKeys
            ],
            Params
        },
    ?event_debug(
        {sig_input,
            {string,
                hb_util:bin(
                    hb_structured_fields:dictionary(
                        #{ <<"comm">> => SFSigInput }
                    )
                )
            }
        }
    ),
    {ok, SigName, SFSig, SFSigInput}.

%% @doc Default commitment ID derivation used on both encode and decode
%% when no explicit `id' parameter is present. 32-byte sigs are used
%% directly; longer sigs are rehashed with sha-256.
derived_commitment_id(Sig) when byte_size(Sig) == 32 ->
    hb_util:human_id(Sig);
derived_commitment_id(Sig) ->
    hb_util:human_id(crypto:hash(sha256, Sig)).

%% @doc HTTPSig derives its committer; other codecs transport theirs explicitly.
get_additional_params(Commitment = #{
        <<"commitment-device">> := <<"httpsig@1.0">>, <<"committer">> := _ }) ->
    get_additional_params(maps:remove(<<"committer">>, Commitment));
get_additional_params(Commitment) ->
    AdditionalParams =
        sets:to_list(
            sets:subtract(
                sets:from_list(maps:keys(Commitment)),
                sets:from_list(
                    [
                        <<"alg">>,
                        <<"keyid">>,
                        <<"tag">>,
                        <<"created">>,
                        <<"expires">>,
                        <<"nonce">>,
                        <<"committed">>,
                        <<"signature">>,
                        <<"type">>,
                        <<"id">>,
                        <<"commitment-device">>
                    ]
                )
            )
        ),
    lists:map(fun(Param) ->
        ParamValue = maps:get(Param, Commitment),
        case ParamValue of
            Val when is_atom(Val) ->
                {Param, {string, atom_to_binary(Val, utf8)}};
            Val when is_binary(Val) ->
                {Param, {string, Val}};
            Val when is_list(Val) ->
                {Param, {string, list_to_binary(lists:join(<<", ">>, Val))}};
            Val when is_map(Val) ->
                Map = nested_map_to_string(Val),
                {Param, {string, list_to_binary(lists:join(<<", ">>, Map))} }
        end
    end, AdditionalParams).

nested_map_to_string(Map) ->
    lists:map(fun(I) ->
        case maps:get(I, Map) of
            Val when is_map(Val) ->
                Name = encode_tag_name(maps:get(<<"name">>, Val)),
                Value = hb_util:encode(maps:get(<<"value">>, Val)),
                <<I/binary, ":", Name/binary, ":", Value/binary>>;
            Val ->
                Val
        end
    end, maps:keys(Map)).

%% @doc Percent-encode an original tag name that holds `%', `:', `,', `"',
%% `\' or a byte outside printable ASCII. Other names are sent as they are.
encode_tag_name(Name) ->
    case lists:any(fun escaped_tag_byte/1, binary_to_list(Name)) of
        true -> hb_escape:encode(Name);
        false -> Name
    end.

%% @doc Whether an original tag name byte needs escaping.
escaped_tag_byte(C) ->
    lists:member(C, "%:,\"\\") orelse C < 16#20 orelse C > 16#7e.

%% @doc Take a message with a `signature' and `signature-input' key pair and
%% return a map of commitments.
siginfo_to_commitments(
        Msg =
            #{
                <<"signature">> := <<"comm-", SFSigBin/binary>>,
                <<"signature-input">> := <<"comm-", SFSigInputBin/binary>>
            },
        BodyKeys,
        Opts) ->
    % Parse the signature and signature-input structured-fields.
    SFSigs = hb_structured_fields:parse_dictionary(SFSigBin),
    SFSigsInputs = hb_structured_fields:parse_dictionary(SFSigInputBin),
    % Group parsed signature inputs and signatures into tuple pairs by their
    % name.
    CommitmentSFs =
        [
            {SFSig, element(2, lists:keyfind(SFSigName, 1, SFSigsInputs))}
        ||
            {SFSigName, SFSig} <- SFSigs
        ],
    % Convert each tuple into a commitment and its ID.
    CommitmentMessages =
        lists:map(
            fun ({SFSig, SFSigInput}) ->
                {ok, ID, Commitment} =
                    sf_siginfo_to_commitment(
                        Msg,
                        BodyKeys,
                        SFSig,
                        SFSigInput,
                        Opts
                    ),
                {ID, Commitment}
            end,
            CommitmentSFs
        ),
    % Convert the list of commitments into a map.
    maps:from_list(CommitmentMessages);
siginfo_to_commitments(_Msg, _BodyKeys, _Opts) ->
    % If the message does not contain a `signature' or `signature-input' key,
    % we return an empty map.
    #{}.

%% @doc Take a signature and signature-input as parsed structured-fields and 
%% return a commitment.
sf_siginfo_to_commitment(Msg, BodyKeys, SFSig, SFSigInput, Opts) ->
    % Extract the signature and signature-input from the structured-fields.
    {item, {binary, Sig}, []} = SFSig,
    {list, SigInput, ParamsKV} = SFSigInput,
    % Generate a commitment message from the signature-input parameters.
    Commitment1 =
        maps:from_list(
            lists:map(
                fun ({Key, {binary, Bin}}) -> {Key, hb_util:encode(Bin)};
                    ({Key, BareItem}) ->
                    Item =
                        case hb_structured_fields:from_bare_item(BareItem) of
                            Res when is_binary(Res) ->
                                decoding_nested_map_binary(Res);
                            Res ->
                                Res
                        end,
                    {Key, Item}
                end,
                ParamsKV
            )
        ),
    % Generate the `commitment-device' key and optionally, its `type' key from
    % the `alg' key.
    CommitmentDeviceKeys = commitment_to_device_specifiers(Commitment1, Opts),
    % Merge the commitment parameters with the commitment device, removing the
    % `alg' key.
    Commitment2 =
        maps:merge(
            CommitmentDeviceKeys,
            maps:remove(<<"alg">>, Commitment1)
        ),
    % Generate the committed keys by parsing the signature-input list. Other
    % devices list their `committed' keys in order, percent-encoded.
    RawCommittedKeys =
        [
            Key
        ||
            {item, {string, Key}, []} <- SigInput
        ],
    CommittedKeys =
        case Commitment2 of
            #{ <<"commitment-device">> := <<"httpsig@1.0">> } ->
                from_siginfo_keys(Msg, BodyKeys, RawCommittedKeys);
            _ ->
                lists:map(fun hb_escape:decode/1, RawCommittedKeys)
        end,
    % Merge and cleanup the output:
    % 1. Decode `keyid' and `signature' to raw bytes.
    % 2. Filter undefined keys.
    % 3. Use the transported `id' parameter when present (content-addressed
    %    devices), otherwise fall back to `derived_commitment_id/1'.
    % 4. Keep a transported committer, or derive it from the HTTPSig keyid.
    Commitment3 =
        Commitment2#{
            <<"signature">> => hb_util:encode(Sig),
            <<"committed">> => CommittedKeys
        },
    {ID, Commitment4} =
        case maps:take(<<"id">>, Commitment3) of
            {ExplicitID, Stripped} -> {ExplicitID, Stripped};
            error                  -> {derived_commitment_id(Sig), Commitment3}
        end,
    KeyID = maps:get(<<"keyid">>, Commitment4, <<>>),
    Commitment5 =
        case dev_httpsig_keyid:keyid_to_committer(KeyID) of
            undefined ->
                Commitment4;
            Committer ->
                Commitment4#{
                    <<"committer">> =>
                        maps:get(<<"committer">>, Commitment4, Committer)
                }
        end,
    % Return the commitment and calculated ID.
    {ok, ID, Commitment5}.

decoding_nested_map_binary(Bin) ->
    MapBinary =
        lists:foldl(
            fun (X, Acc) ->
                case binary:split(X, <<":">>, [global]) of
                    [ID, Key, Value] ->
                        Acc#{
                            ID => #{ 
                                <<"name">> => hb_escape:decode(Key),
                                <<"value">> => hb_util:decode(Value)
                            }
                        };
                    _ ->
                        X
                end
            end,
            #{},
            binary:split(Bin, <<", ">>, [global])
        ),
    case MapBinary of
        Res when is_map(Res) ->
            Res;
        Res ->
            Res
    end.

%% @doc Normalize a list of AO-Core keys to their equivalents in `httpsig@1.0'
%% format. This involves:
%% - If the HTTPSig message given has an `ao-body-key' key and the committed keys
%%   list contains it, we replace it in the list with the `body' key and add the
%%   `ao-body-key' key.
%% - If the list contains a `body' key, we replace it with the `content-digest'
%%   key.
%% - Otherwise, we return the list unchanged.
%% Commitments of devices other than `httpsig@1.0' send their `committed'
%% lists as they are, in order and percent-encoded: those devices verify them.
to_siginfo_keys(Msg, Commitment = #{
        <<"commitment-device">> := <<"httpsig@1.0">> }, Opts) ->
    {ok, _EncMsg, EncComm, _} =
        dev_httpsig:normalize_for_encoding(Msg, Commitment, Opts),
    maps:get(<<"committed">>, EncComm);
to_siginfo_keys(_Msg, Commitment, Opts) ->
    lists:map(
        fun hb_escape:encode/1,
        hb_util:message_to_ordered_list(
            maps:get(<<"committed">>, Commitment, []),
            Opts
        )
    ).

%% @doc Normalize a list of `httpsig@1.0' keys to their equivalents in AO-Core
%% format. Replace `content-digest' with the body keys, remove component prefixes,
%% and restore the body's original key. A multipart `content-type' header is not
%% a message key; the message's own `content-type' may be in the body instead.
from_siginfo_keys(HTTPEncMsg, BodyKeys, SigInfoCommitted) ->
    % 1. Replace the `content-digest' component with the body keys, then remove
    %    specifiers from the other keys and decode them. A key of the message
    %    named `content-digest' is one of the body keys.
    WithBody =
        lists:flatmap(
            fun(<<"content-digest">>) -> BodyKeys;
               (<<"content-type">>) ->
                    case maps:get(<<"content-type">>, HTTPEncMsg, undefined) of
                        <<"multipart/", _/binary>> -> [];
                        _ -> [<<"content-type">>]
                    end;
               (<<"@", Key/binary>>) -> [hb_escape:decode(Key)];
               (Key) -> [hb_escape:decode(Key)]
            end,
            SigInfoCommitted
        ),
    % 2. Replace the `body' key again with the value of the `ao-body-key' key,
    %    if present.
    ?event_debug(
        {from_siginfo_keys,
            {body_keys, BodyKeys},
            {raw_committed, SigInfoCommitted},
            {with_body, {explicit, WithBody}}
        }
    ),
    ListWithoutBodyKey =
        case lists:member(<<"ao-body-key">>, WithBody) of
            true ->
                WithOrigBodyKey =
                    hb_util:list_replace(
                        WithBody,
                        <<"body">>,
                        maps:get(<<"ao-body-key">>, HTTPEncMsg)
                    ),
                ?event_debug({with_orig_body_key, WithOrigBodyKey}),
                WithOrigBodyKey -- [<<"ao-body-key">>];
            false ->
                WithBody
        end,
    Normalized =
        hb_ao:normalize_keys(
            lists:map(
                fun hb_link:remove_link_specifier/1,
                ListWithoutBodyKey
            )
        ),
    List = hb_util:message_to_ordered_list(Normalized),
    ?event_debug({from_siginfo_keys, {list, List}}),
    List.

%% @doc Convert committed keys to their siginfo format. This involves removing
%% the `body' key from the committed keys, if present, and replacing it with
%% the `content-digest' key.
committed_keys_to_siginfo(Msg) when is_map(Msg) ->
    committed_keys_to_siginfo(hb_util:message_to_ordered_list(Msg));
committed_keys_to_siginfo([]) -> [];
committed_keys_to_siginfo([<<"body">> | Rest]) ->
    [<<"content-digest">> | Rest];
committed_keys_to_siginfo([Key | Rest]) ->
    [Key | committed_keys_to_siginfo(Rest)].

%% @doc Convert an `alg` to a commitment device. If the `alg' has the form of
%% a device specifier (`x@y.z...[/type]'), return the device. Otherwise, we 
%% assume that the `alg' is a `type' of the `httpsig@1.0' algorithm.
%% `type' is an optional key that allows for subtyping of the algorithm. When 
%% provided, in the `alg' it is parsed and returned as the `type' key in the
%% commitment message.
commitment_to_device_specifiers(Commitment, Opts) when is_map(Commitment) ->
    commitment_to_device_specifiers(maps:get(<<"alg">>, Commitment), Opts);
commitment_to_device_specifiers(Alg, _Opts) ->
    case binary:split(Alg, <<"@">>) of
        [Type] ->
            % The `alg' is not a device specifier, so we assume that it is a
            % type of the `httpsig@1.0' algorithm.
            #{
                <<"commitment-device">> => <<"httpsig@1.0">>,
                <<"type">> => Type
            };
        [DevName, Specifiers] ->
            % The `alg' is a device specifier. We determine if a type is present
            % by splitting on the `/` character.
            case binary:split(Specifiers, <<"/">>) of
                [_Version] ->
                    % The `alg' is a device specifier without a type.
                    #{
                        <<"commitment-device">> => Alg
                    };
                [Version, Type] ->
                    % The `alg' is a device specifier with a type.
                    #{
                        <<"commitment-device">> =>
                            <<DevName/binary, "@", Version/binary>>,
                        <<"type">> => Type
                    }
            end
    end.

%% @doc Calculate an `alg' string from a commitment message, using its 
%% `commitment-device' and optionally, its `type' key.
commitment_to_alg(#{ <<"commitment-device">> := <<"httpsig@1.0">>, <<"type">> := Type }, _Opts) ->
    Type;
commitment_to_alg(Commitment, _Opts) ->
    Type =
        case maps:get(<<"type">>, Commitment, undefined) of
            undefined -> <<>>;
            TypeSpecifier -> <<"/", TypeSpecifier/binary>>
        end,
    CommitmentDevice = maps:get(<<"commitment-device">>, Commitment),
    <<CommitmentDevice/binary, Type/binary>>.

%% @doc Generate a signature name from a commitment. The commitment message is
%% not expected to be complete: Only the `commitment-device`, and the
%% `committer' or `keyid' keys are required.
commitment_to_sig_name(Commitment) ->
    BaseStr =
        case maps:get(<<"committer">>, Commitment, undefined) of
            undefined -> maps:get(<<"keyid">>, Commitment);
            Committer ->
                <<
                    (hb_util:to_hex(binary:part(hb_util:native_id(Committer), 1, 8)))
                        /binary
                >>
        end,
    DeviceStr =
        binary:replace(
            maps:get(
                <<"commitment-device">>,
                Commitment
            ),
            <<"@">>,
            <<"-">>
        ),
    <<DeviceStr/binary, ".", BaseStr/binary>>.

%% @doc Normalize key parameters to ensure their names are correct for inclusion
%% in the `signature-input' and associated keys.
add_derived_specifiers(ComponentIdentifiers) ->
    % Remove the @ prefix from the component identifiers, if present.
    Stripped =
        lists:map(
            fun(<<"@", Key/binary>>) -> Key; (Key) -> Key end,
            ComponentIdentifiers
        ),
    % Add the @ prefix to the component identifiers, if they are derived.
    lists:flatten(
        lists:map(
            fun(Key) ->
                case lists:member(Key, ?DERIVED_COMPONENTS) of
                    true -> << "@", Key/binary >>;
                    false -> Key
                end
            end,
            Stripped
        )
    ).

%% @doc Remove derived specifiers from a list of component identifiers.
remove_derived_specifiers(ComponentIdentifiers) ->
    lists:map(
        fun(<<"@", Key/binary>>) ->
            Key;
        (Key) ->
            Key
        end,
        ComponentIdentifiers
    ).

%%% Tests.

parse_alg_test() ->
    ?assertEqual(
        commitment_to_device_specifiers(#{ <<"alg">> => <<"rsa-pss-sha512">> }, #{}),
        #{
            <<"commitment-device">> => <<"httpsig@1.0">>,
            <<"type">> => <<"rsa-pss-sha512">>
        }
    ),
    ?assertEqual(
        commitment_to_device_specifiers(
            #{ <<"alg">> => <<"ans104@1.0/rsa-pss-sha256">> },
            #{}),
        #{
            <<"commitment-device">> => <<"ans104@1.0">>,
            <<"type">> => ?RSA_SIGN_TYPE
        }
    ).

%% @doc Test that tag values with special characters are correctly encoded and
%% decoded.
escaped_value_test() ->
    KeyID = crypto:strong_rand_bytes(32),
    Committer = hb_util:human_id(ar_wallet:to_address(KeyID)),
    Signature = crypto:strong_rand_bytes(512),
    ID = hb_util:human_id(crypto:hash(sha256, Signature)),
    Commitment = #{
        <<"committed">> => [],
        <<"committer">> => Committer,
        <<"commitment-device">> => <<"tx@1.0">>,
        <<"keyid">> => <<"publickey:", (hb_util:encode(KeyID))/binary>>,
        <<"original-tags">> => #{
            <<"1">> => #{
                <<"name">> => <<"Key">>,
                <<"value">> => <<"value">>
            },
            <<"2">> => #{
                <<"name">> => <<"Quotes">>,
                <<"value">> => <<"{\"function\":\"mint\"}">>
            }
        },
        <<"signature">> => hb_util:encode(Signature),
        <<"type">> => ?RSA_SIGN_TYPE
    },
    SigInfo = commitments_to_siginfo(#{}, #{ ID => Commitment }, #{}),
    Commitments = siginfo_to_commitments(SigInfo, #{}, #{}),
    ?event(debug_test, {siginfo, {explicit, SigInfo}}),
    ?event(debug_test, {commitments, {explicit, Commitments}}),
    ?assertEqual(#{ ID => Commitment }, Commitments).

%% @doc Original tag names that the `original-tags' string can carry are sent
%% as they are; other names are percent-encoded and decode to themselves.
original_tag_names_test() ->
    Tag = fun(Name, Value) -> #{ <<"name">> => Name, <<"value">> => Value } end,
    Tags =
        #{
            <<"1">> => Tag(<<"Action">>, <<"Transfer">>),
            <<"2">> => Tag(<<"a:b, c">>, <<"x">>),
            <<"3">> => Tag(<<"%41">>, <<"y">>),
            <<"4">> => Tag(<<255>>, <<"z">>)
        },
    Wire = nested_map_to_string(Tags),
    Plain = <<"1:Action:", (hb_util:encode(<<"Transfer">>))/binary>>,
    ?assert(lists:member(Plain, Wire)),
    ?assertEqual(
        Tags,
        decoding_nested_map_binary(iolist_to_binary(lists:join(<<", ">>, Wire)))
    ).
