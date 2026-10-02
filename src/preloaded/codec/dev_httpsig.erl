%%% @doc This module implements HTTP Message Signatures as described in RFC-9421
%%% (https://datatracker.ietf.org/doc/html/rfc9421), as an AO-Core device.
%%% It implements the codec standard (from/1, to/1), as well as the optional
%%% commitment functions (id/3, sign/3, verify/3). The commitment functions
%%% are found in this module, while the codec functions are relayed to the 
%%% `dev_httpsig_conv' module.
-module(dev_httpsig).
-device_libraries([lib_arweave_common]).
%%% Codec API functions
-export([to/3, to_hint/3, from/3]).
%%% Uni-directional codec support (_to_ binary/header+body components), but not 
%%% back.
-export([serialize/2, serialize/3]).
%%% Commitment API functions
-export([commit/3, verify/3]).
%%% Public API functions
-export([add_content_digest/2, normalize_for_encoding/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%%% Routing functions for the `dev_httpsig_conv' module
-spec to(#{ _ => _ }, #{ _ => _ }, map()) -> term().
to(Msg, Req, Opts) -> dev_httpsig_conv:to(Msg, Req, Opts).
-spec from(#{ _ => _ }, #{ _ => _ }, map()) -> term().
from(Msg, Req, Opts) -> dev_httpsig_conv:from(Msg, Req, Opts).

%% @doc Generate the `Opts' to use during AO-Core operations in the codec.
opts(RawOpts) ->
    RawOpts#{
        <<"hashpath">> => ignore,
        <<"cache-control">> => [<<"no-cache">>, <<"no-store">>],
        <<"force-message">> => false
    }.

%% @doc A helper utility for creating a direct encoding of a HTTPSig message.
%% 
%% This function supports two modes of operation:
%% 1. `format: binary`, yielding a raw binary HTTP/1.1-style response that can 
%%    either be stored or emitted raw accross a transport medium.
%% 2. `format: components`, yielding a message containing `headers` and `body`
%%    keys, suitable for use in connecting to HTTP-response flows implemented 
%%    by other servers.
%% 
%% Optionally, the `index` key can be set to override resolution of the default
%% index page into HTTP responses that do not contain their own `body` field.
serialize(Msg, Opts) -> serialize(Msg, #{}, Opts).
-spec serialize(
    #{ _ => _ },
    #{ format => binary(), index => binary(), _ => _ },
    #{ _ => _ }
) -> {ok, binary() | #{ headers := #{ _ => _ }, body := _, _ => _ }}.
serialize(Msg, #{ <<"format">> := <<"components">> }, Opts) ->
    % Convert to HTTPSig via TABM through calling `hb_message:convert` rather
    % than executing `to/3` directly. This ensures that our responses are 
    % normalized.
    {ok, EncMsg} = hb_message:convert(Msg, <<"httpsig@1.0">>, Opts),
    {ok,
        #{
            <<"body">> => hb_maps:get(<<"body">>, EncMsg, <<>>),
            <<"headers">> => hb_maps:without([<<"body">>], EncMsg)
        }
    };
serialize(Msg, _Req, Opts) ->
    % We assume the default format of `binary` if none of the prior clauses
    % match.
    HTTPSig = hb_message:convert(Msg, <<"httpsig@1.0">>, Opts), 
    {ok, dev_httpsig_conv:encode_http_msg(HTTPSig, Opts) }.

-spec verify(
    #{ _ => _ },
    #{ signature := binary(), type := binary(), _ => _ },
    #{ _ => _ }
) -> {ok, boolean()} | {failure, _}.
verify(Base, Req, RawOpts) ->
    Opts = opts(RawOpts),
    % Verify the commitment's ID as well as the presence of its committed keys.
    maybe
        [] ?= missing_keys(Base, Req, Opts),
        ID = dev_httpsig_siginfo:derived_commitment_id(
            hb_util:decode(maps:get(<<"signature">>, Req))),
        true ?= maps:is_key(ID, maps:get(<<"commitments">>, Base, #{})),
        do_verify(Base, Req, Opts)
    else
        Failure ->
            ?event(httpsig_verify, {verify, {invalid_commitment, Failure}}),
            {ok, false}
    end.

%% @doc Verify a commitment whose committed keys the base carries. A
%% rsa-pss-sha512 commitment is verified by regenerating the signature base
%% and validating against the signature.
do_verify(Base, Req, Opts) ->
    {ok, EncMsg, EncComm, _} = normalize_for_encoding(Base, Req, Opts),
    SigBase = signature_base(EncMsg, EncComm, Opts),
    KeyRes = dev_httpsig_keyid:req_to_key_material(Req, Opts),
    RawSignature = hb_util:decode(Signature = maps:get(<<"signature">>, Req)),
    ?event_debug(debug_httpsig,
        {
            httpsig_verifying,
            {signature, Signature},
            {parsed_key_material, KeyRes},
            {req, Req},
            {signature_base, {string, SigBase}}
        }
    ),
    case {KeyRes, maps:get(<<"type">>, Req)} of
        {{ok, publickey, Key, KeyID}, <<"rsa-pss-sha512">>} ->
            ?event(httpsig_verify, {verify, {rsa_pss_sha512, {sig_base, SigBase}}}),
            {
                ok,
                maps:get(<<"committer">>, Req, undefined) =:=
                    dev_httpsig_keyid:keyid_to_committer(publickey, KeyID)
                andalso binary:decode_unsigned(Key) >= (1 bsl 2047)
                andalso ar_wallet:verify(
                    {{rsa, 65537}, Key},
                    SigBase,
                    RawSignature,
                    sha512
                )
            };
        {{ok, Scheme, Key, KeyID}, <<"hmac-sha256">>}
                when Scheme =:= constant; Scheme =:= secret ->
            % Generate the HMAC from the key and signature base.
            ActualHMac =
                hb_util:human_id(
                    crypto:mac(hmac, sha256, Key, SigBase)
                ),
            ?event(httpsig_verify,
                {verify,
                    {hmac_sha256,
                        {keyid, KeyID},
                        {sig_base, SigBase},
                        {actual_hmac, {string, ActualHMac}},
                        {signature, {string, Signature}},
                        {matches, Signature =:= ActualHMac}
                    }
                }),
            {ok, Signature =:= ActualHMac andalso
                maps:get(<<"committer">>, Req, undefined) =:=
                    dev_httpsig_keyid:keyid_to_committer(Scheme, KeyID)};
        {{ok, _, _, _}, _Type} ->
            {ok, false};
        {{error, Reason}, _Type} ->
            ?event(httpsig_verify, {verify, {error, Reason}}),
            {ok, false};
        {{failure, Info}, _Type} ->
            ?event(httpsig_verify, {verify, {failure, Info}}),
            {failure, Info}
    end.

%% @doc Whether a wallet holds an RSA key, in either of the forms that
%% `ar_wallet' signs with.
rsa_wallet({{rsa, 65537}, _, _}) -> true;
rsa_wallet({{{rsa, 65537}, _, _}, {{rsa, 65537}, _}}) -> true;
rsa_wallet(_) -> false.

%% @doc Commit to a message using the HTTP-Signature format. We use the `type'
%% parameter to determine the type of commitment to use. If the `type' parameter
%% is `signed', we default to the rsa-pss-sha512 algorithm. If the `type'
%% parameter is `unsigned', we default to the hmac-sha256 algorithm.
-spec commit(
    #{ _ => _ },
    #{
        type := binary(),
        bundle => boolean(),
        committed => [_] | #{ _ => _ },
        _ => _
    },
    #{ _ => _ }
) -> {ok, #{ _ => _ }}.
commit(Msg, Req = #{ <<"type">> := <<"unsigned">> }, Opts) ->
    commit(Msg, Req#{ <<"type">> => <<"hmac-sha256">> }, Opts);
commit(Msg, Req = #{ <<"type">> := <<"signed">> }, Opts) ->
    commit(Msg, Req#{ <<"type">> => <<"rsa-pss-sha512">> }, Opts);
commit(MsgToSign, Req = #{ <<"type">> := <<"rsa-pss-sha512">> }, RawOpts) ->
    ?event(
        {generating_rsa_pss_sha512_commitment, {msg, MsgToSign}, {req, Req}}
    ),
    Opts = opts(RawOpts),
    Wallet = hb_opts:get(priv_wallet, no_viable_wallet, Opts),
    if Wallet =:= no_viable_wallet ->
        throw({cannot_commit, no_viable_wallet, MsgToSign});
    true ->
        ok
    end,
    % The algorithm signs with an RSA key; a wallet of another type cannot
    % produce a commitment that this device verifies.
    case rsa_wallet(Wallet) of
        true -> ok;
        false -> throw({cannot_commit, 'unsupported-key-type', MsgToSign})
    end,
    % Utilize the hashpath, if present, as the tag for the commitment.
    MaybeTagMap =
        case MsgToSign of
            #{ <<"priv">> := #{ <<"hashpath">> := HP }} -> #{ <<"tag">> => HP };
            _ -> #{}
        end,
    % Generate the unsigned commitment and signature base.
    ToCommit = hb_ao:normalize_keys(keys_to_commit(MsgToSign, Req, Opts)),
    ?event_debug({to_commit, ToCommit}),
    UnsignedCommitment =
        maybe_bundle_tag_commitment(
            MaybeTagMap#{
                <<"commitment-device">> => <<"httpsig@1.0">>,
                <<"type">> => <<"rsa-pss-sha512">>,
                <<"keyid">> =>
                    <<
                        "publickey:",
                        (base64:encode(ar_wallet:to_pubkey(Wallet)))/binary
                    >>,
                <<"committer">> =>
                    hb_util:human_id(ar_wallet:to_address(Wallet)),
                <<"committed">> => ToCommit
            },
            Req,
            Opts
        ),
    {ok, EncMsg, EncComm, ModCommittedKeys} =
        normalize_for_encoding(MsgToSign, UnsignedCommitment, Opts),
    ?event_debug({encoded_to_httpsig_for_commitment, MsgToSign}),
    % Generate the signature base
    SignatureBase = signature_base(EncMsg, EncComm, Opts),
    ?event_debug({rsa_signature_base, {string, SignatureBase}}),
    ?event_debug({mod_committed_keys, ModCommittedKeys}),
    % Sign the signature base
    Signature = ar_wallet:sign(Wallet, SignatureBase, sha512),
    % Generate the ID of the signature
    ID = hb_util:human_id(crypto:hash(sha256, Signature)),
    ?event_debug({rsa_commit, {committed, ToCommit}}),
    % Calculate the ID and place the signature into the `commitments' key of the
    % message. After, we call `commit' again to add the hmac to the new
    % message.
    {
        ok,
        MsgToSign#{
            <<"commitments">> =>
                (maps:get(<<"commitments">>, MsgToSign, #{}))#{
                    ID =>
                        UnsignedCommitment#{
                            <<"signature">> => hb_util:encode(Signature),
                            <<"committed">> => ModCommittedKeys
                        }
                }
        }
    };
commit(BaseMsg, Req = #{ <<"type">> := <<"hmac-sha256">> }, RawOpts) ->
    % Extract the key material from the request.
    Opts = opts(RawOpts),
    ?event_debug({req_to_key_material, {priv_req, Req}}),
    {ok, Scheme, Key, KeyID} = dev_httpsig_keyid:req_to_key_material(Req, Opts),
    Committer = dev_httpsig_keyid:keyid_to_committer(Scheme, KeyID),
    % Remove any existing hmac commitments with the given keyid before adding
    % the new one.
    Msg =
        hb_message:without_commitments(
            #{
                <<"commitment-device">> => <<"httpsig@1.0">>,
                <<"type">> => <<"hmac-sha256">>,
                <<"keyid">> => KeyID
            },
            BaseMsg,
            Opts
        ),
    % Extract the base commitments from the message.
    Commitments = maps:get(<<"commitments">>, Msg, #{}),
    CommittedKeys = keys_to_commit(Msg, Req, Opts),
    % Create the commitment with the appropriate keyid, committed keys, and 
    % bundle specifier.
    CommitmentWithoutCommitter = #{
        <<"commitment-device">> => <<"httpsig@1.0">>,
        <<"type">> => <<"hmac-sha256">>,
        <<"keyid">> => KeyID,
        <<"committed">> => hb_ao:normalize_keys(CommittedKeys)
    },
    % If the committer is undefined, we do not need to add the `committer' key.
    BaseCommitment =
        if Committer =:= undefined -> CommitmentWithoutCommitter;
        true -> CommitmentWithoutCommitter#{ <<"committer">> => Committer }
        end,
    UnauthedCommitment =
        maybe_bundle_tag_commitment(
            BaseCommitment,
            Req,
            Opts
        ),
    {ok, EncMsg, EncComm, ModCommittedKeys} =
        normalize_for_encoding(Msg, UnauthedCommitment, Opts),
    SigBase = signature_base(EncMsg, EncComm, Opts),    
    HMac = hb_util:human_id(crypto:mac(hmac, sha256, Key, SigBase)),
    ?event_debug(
        debug_commitments,
        {hmac_commit,
            {type, <<"hmac-sha256">>},
            {keyid, KeyID},
            {committer, Committer},
            {committed, CommittedKeys},
            {mod_committed_keys, ModCommittedKeys},
            {sig_base, SigBase},
            {hmac, HMac}
        }
    ),
    Res =
        {
            ok,
            Msg#{
                <<"commitments">> =>
                    Commitments#{
                        HMac =>
                            UnauthedCommitment#{
                                <<"signature">> => HMac,
                                <<"committed">> => ModCommittedKeys
                            }
                    }
            }
        },
    ?event_debug(debug_commitments, {hmac_generation_complete, Res}),
    Res.

%% @doc Annotate the commitment with the `bundle' key if the request contains
%% it.
maybe_bundle_tag_commitment(Commitment, Req, _Opts) ->
    case hb_util:atom(maps:get(<<"bundle">>, Req, false)) of
        true -> Commitment#{ <<"bundle">> => <<"true">> };
        false -> Commitment
    end.

%% @doc Apply the bundle state of an HTTPSig commitment to a conversion.
to_hint(Msg, Req, Opts) ->
    case lib_arweave_common:bundle_hint(<<"httpsig@1.0">>, Msg, Req, Opts) of
        not_found -> {ok, Req};
        Hint -> Hint
    end.

%% @doc Derive the set of keys to commit to from a `commit` request and a 
%% base message.
keys_to_commit(_Base, #{ <<"committed">> := Explicit}, _Opts) ->
    % Case 1: Explicitly provided keys to commit.
    % Add `+link` specifiers to the user given list as necessary, in order for
    % their given keys to match the HTTPSig encoded TABM form.
    hb_util:list_to_numbered_message(Explicit);
keys_to_commit(Base = #{ <<"commitments">> := Commitments }, _Req, Opts)
        when ?IS_EMPTY_MESSAGE(Commitments) ->
    default_keys_to_commit(Base, Opts);
keys_to_commit(Base, _Req, Opts) when not is_map_key(<<"commitments">>, Base) ->
    default_keys_to_commit(Base, Opts);
keys_to_commit(Base, _Req, Opts) ->
    % Extract the set of committed keys from the message.
    case hb_message:committed(Base, #{ <<"committers">> => <<"all">> }, opts(Opts)) of
        [] ->
            % Case 3: Default to all keys in the TABM-encoded message, aside
            % metadata.
            default_keys_to_commit(Base, Opts);
        Keys ->
            % Case 2: Replicate the raw keys that the existing commitments have
            % used. This leads to a message whose commitments can be 'stacked'
            % and represented together in HTTPSig format.
            hb_util:list_to_numbered_message(Keys)
    end.

default_keys_to_commit(Base, Opts) ->
    hb_util:list_to_numbered_message(
        lists:map(
            fun hb_link:remove_link_specifier/1,
            hb_util:to_sorted_keys(Base, Opts)
                -- [<<"commitments">>, <<"priv">>]
        )
    ).

%% @doc If the `body' key is present and a binary, replace it with a
%% content-digest.
add_content_digest(Msg, _Opts) ->
    case maps:get(<<"body">>, Msg, not_found) of
        Body when is_binary(Body) ->
            % Remove the body from the message and add the content-digest,
            % encoded as a structured field.
            (maps:without([<<"body">>], Msg))#{
                <<"content-digest">> =>
                    hb_util:bin(hb_structured_fields:dictionary(
                        #{
                            <<"sha-256">> =>
                                {item, {binary, hb_crypto:sha256(Body)}, []}
                        }
                    ))
            };
        _ -> Msg
    end.

%% @doc Given a base message and a commitment, derive the message and commitment
%% normalized for encoding.
-spec normalize_for_encoding(
    #{ _ => _ },
    #{ committed => [_], _ => _ },
    #{ _ => _ }
) -> {ok, #{ _ => _ }, #{ committed := [_], _ => _ }, [_]}.
normalize_for_encoding(Msg, Commitment, Opts) ->
    % Extract the requested keys to include in the signature base.
    RawInputs = committed_keys(Commitment, Opts),
    Inputs = input_keys(Msg, RawInputs),
    ?event_debug({inputs, {list, Inputs}}),
    % A commitment is over every key it lists. A committed key that the
    % message lacks cannot be left out of the signature base silently: the
    % commitment would then be encoded over a message that its signature does
    % not verify.
    case missing_keys(Msg, Commitment, Opts) of
        [] -> ok;
        Missing ->
            throw(
                {committed_key_missing,
                    {keys, Missing},
                    {commitment, Commitment},
                    {msg, Msg}
                }
            )
    end,
    % Filter the message to the requested keys and their types, then encode it.
    MsgWithOnlyInputs =
        with_types(
            maps:with(
                Inputs ++ lists:map(fun hb_escape:encode/1, Inputs),
                Msg
            ),
            Inputs,
            Msg,
            Opts
        ),
    ?event_debug({msg_with_only_inputs, {priv_msg, maps:without([<<"commitments">>], MsgWithOnlyInputs)}}),
    {ok, EncodedWithSigInfo} =
        to(
            maps:without([<<"commitments">>], MsgWithOnlyInputs),
            #{
                <<"bundle">> =>
                    hb_util:atom(maps:get(<<"bundle">>, Commitment, false))
            },
            Opts
        ),
    % Remove the signature and signature-input keys from the encoded message,
    % convert the `body' key to a `content-digest' key, if present.
    Encoded = add_content_digest(EncodedWithSigInfo, Opts),
    % Transform the list of requested keys to their `httpsig@1.0' equivalents.
    EncodedKeys = maps:keys(Encoded),
    EncodedKeysWithBodyKey =
        case hb_maps:get(<<"ao-body-key">>, EncodedWithSigInfo, not_found) of
            not_found ->
                EncodedKeys;
            AOBodyKey ->
                hb_util:list_replace(
                    EncodedKeys,
                    AOBodyKey,
                    [<<"body">>, <<"ao-body-key">>]
                )
        end,
    % The keys to be used in encodings of the message:
    KeysForEncoding =
        hb_util:list_replace(
            EncodedKeysWithBodyKey,
            <<"body">>,
            <<"content-digest">>
        ),
    % Calculate the keys that have been removed from the message, as a result
    % of being added to the body. These keys will need to be removed from the
    % `committed' list and re-added where the `content-digest' was in the
    % `from_siginfo_keys' call. A `content-digest' key of the message is always
    % in the body: the header of that name is the digest of the body.
    BodyKeys =
        lists:filter(
            fun(Key) ->
                Key =:= <<"content-digest">> orelse
                    not key_present(Key, Encoded) orelse
                    (Key =:= <<"content-type">> andalso
                        maps:get(Key, MsgWithOnlyInputs, undefined) =/=
                            maps:get(Key, Encoded, undefined))
            end,
            RawInputs
        ),
    KeysForCommitment =
        dev_httpsig_siginfo:from_siginfo_keys(
            EncodedWithSigInfo,
            BodyKeys,
            KeysForEncoding
        ),
    ?event_debug(debug_httpsig,
        {normalized_for_encoding,
            {raw_inputs, Inputs},
            {inputs_for_encoding, KeysForEncoding},
            {final_for_commitment_message, KeysForCommitment},
            {encoded_message, Encoded}
        }
    ),
    {
        ok,
        Encoded,
        Commitment#{ <<"committed">> => KeysForEncoding },
        KeysForCommitment
    }.

%% @doc The keys a commitment lists as committed, in order.
committed_keys(Commitment, Opts) ->
    hb_util:message_to_ordered_list(
        maps:get(<<"committed">>, Commitment, []),
        Opts
    ).

%% @doc The keys a commitment lists, in the form the message carries them: a
%% key held as a link carries its `+link' specifier.
input_keys(Msg, RawInputs) ->
    lists:map(
        fun(Key) ->
            NormalizedKey = hb_ao:normalize_key(Key),
            case maps:is_key(NormalizedKey, Msg) of
                true -> NormalizedKey;
                false ->
                    case maps:is_key(<<NormalizedKey/binary, "+link">>, Msg) of
                        true -> <<NormalizedKey/binary, "+link">>;
                        false -> NormalizedKey
                    end
            end
        end,
        RawInputs
    ).

%% @doc The committed values with the message's `ao-types' entries for their
%% keys. A commitment covers the types of its values whether or not it lists
%% `ao-types'.
with_types(Values, Keys, #{ <<"ao-types">> := Types }, Opts) ->
    % Unsigned IDs run this function, so `structured@1.0' is called raw: a
    % resolution would read the cache and compute IDs.
    {ok, AllTypes} =
        hb_ao:raw(<<"structured@1.0">>, <<"decode-types">>, Types, #{}, Opts),
    case maps:with(Keys, AllTypes) of
        NoTypes when map_size(NoTypes) =:= 0 -> Values;
        AllTypes -> Values#{ <<"ao-types">> => Types };
        CommittedTypes ->
            {ok, EncodedTypes} =
                hb_ao:raw(
                    <<"structured@1.0">>,
                    <<"encode-types">>,
                    CommittedTypes,
                    #{},
                    Opts
                ),
            Values#{ <<"ao-types">> => EncodedTypes }
    end;
with_types(Values, _Keys, _Msg, _Opts) ->
    Values.

%% @doc The keys a commitment lists that the message does not carry.
missing_keys(Msg, Commitment, Opts) ->
    [
        Key
    ||
        Key <- input_keys(Msg, committed_keys(Commitment, Opts)),
        not key_present(Key, Msg)
    ].

%% @doc Calculate if a key or its `+link' TABM variant is present in a message,
%% as it is or percent-encoded as on the wire.
key_present(Key, Msg) ->
    lists:any(
        fun(K) ->
            is_map_key(K, Msg)
                orelse is_map_key(dev_httpsig_conv:encode_key(K), Msg)
        end,
        [Key, <<Key/binary, "+link">>]
    ).

%% @doc create the signature base that will be signed in order to create the
%% Signature and SignatureInput.
%%
%% This implements a portion of RFC-9421 see:
%% https://datatracker.ietf.org/doc/html/rfc9421#name-creating-the-signature-base
signature_base(EncodedMsg, Commitment, Opts) ->
	ComponentsLines =
        signature_components_line(
            EncodedMsg,
            Commitment,
            Opts
        ),
    ?event_debug({component_identifiers_for_sig_base, {priv_components, ComponentsLines}}),
	ParamsLine = signature_params_line(Commitment, Opts),
    SignatureBase = 
        <<
            ComponentsLines/binary, "\n",
            "\"@signature-params\": ", ParamsLine/binary
        >>,
    ?event_debug(signature_base, {signature_base, {string, SignatureBase}}),
	SignatureBase.

%% @doc Given a list of Component Identifiers and a Request/Response Message
%% context, create the "signature-base-line" portion of the signature base
%% TODO: catch duplicate identifier:
%% https://datatracker.ietf.org/doc/html/rfc9421#section-2.5-7.2.2.5.2.1
%%
%% See https://datatracker.ietf.org/doc/html/rfc9421#section-2.5-7.2.1
signature_components_line(Req, Commitment, _Opts) ->
	ComponentsLines =
        lists:map(
            fun(Name) ->
                case maps:get(Name, Req, not_found) of
                    not_found ->
                        throw(
                            {
                                missing_key_for_signature_component_line,
                                Name,
                                {message, Req},
                                {commitment, Commitment}
                            }
                        );
                    Value ->
                        <<"\"", Name/binary, "\": ", Value/binary>>
                end
            end,
            maps:get(<<"committed">>, Commitment)
        ),
	iolist_to_binary(lists:join(<<"\n">>, ComponentsLines)).

%% @doc construct the "signature-params-line" part of the signature base.
%%
%% See https://datatracker.ietf.org/doc/html/rfc9421#section-2.5-7.3.2.4
signature_params_line(RawCommitment, Opts) ->
    ?event_debug(debug_enc, {signature_params_line, {commitment, RawCommitment}}),
	hb_util:bin(
        hb_structured_fields:list(
            [
                {
                    list,
                    lists:map(
                        fun(Key) -> {item, {string, Key}, []} end,
                        dev_httpsig_siginfo:add_derived_specifiers(
                            hb_util:message_to_ordered_list(
                                maps:get(<<"committed">>, RawCommitment),
                                Opts
                            )
                        )
                    ),
                    signature_params(RawCommitment)
                }
            ]
        )
    ).

signature_params(Commitment) ->
    lists:filtermap(
        fun(Name) ->
            case signature_param(Name, Commitment) of
                undefined -> false;
                Param when is_binary(Param) -> {true, {Name, {string, Param}}};
                Param when is_integer(Param) -> {true, {Name, Param}}
            end
        end,
        [
            <<"alg">>,
            <<"bundle">>,
            <<"created">>,
            <<"expires">>,
            <<"keyid">>,
            <<"nonce">>,
            <<"tag">>
        ]
    ).

signature_param(<<"alg">>, Commitment) ->
    maps:get(<<"type">>, Commitment);
signature_param(Name, Commitment) ->
    maps:get(Name, Commitment, undefined).

%%%
%%% TESTS
%%%

%%% Integration Tests

%% @doc Commitment identities must agree with the verified key and signature.
commitment_identity_test() ->
    Opts = #{ <<"priv-wallet">> => ar_wallet:new() },
    Msg = #{ <<"body">> => <<"authenticated">> },
    Victim = hb_util:human_id(ar_wallet:to_address(ar_wallet:new())),
    Signed = hb_message:commit(Msg, Opts),
    Unsigned = hb_message:commit(Msg, Opts, #{ <<"type">> => <<"unsigned">> }),
    lists:foreach(
        fun(Committed) ->
            ?assert(hb_message:verify(
                Committed, #{ <<"ids">> => <<"all">> }, Opts)),
            Forged = Committed#{ <<"commitments">> => maps:map(
                fun(_, C) -> C#{ <<"committer">> => Victim } end,
                maps:get(<<"commitments">>, Committed)
            ) },
            ?assertNot(hb_message:verify(Forged, all, Opts)),
            Renamed = Committed#{ <<"commitments">> => #{
                Victim => hd(maps:values(maps:get(<<"commitments">>, Committed)))
            } },
            ?assertNot(hb_message:verify(
                Renamed, #{ <<"ids">> => <<"all">> }, Opts))
        end,
        [Signed, Unsigned]
    ),
    Wire = hb_message:convert(Signed, <<"httpsig@1.0">>, Opts),
    Roundtrip = hb_message:convert(
        Wire, <<"structured@1.0">>, <<"httpsig@1.0">>, Opts
    ),
    ?assert(hb_message:verify(Roundtrip, all, Opts)).

%% @doc A publicly known RSA key cannot authenticate an HMAC signer.
public_key_hmac_is_not_authority_test() ->
    {_, {_, Pub}} = ar_wallet:new(),
    Opts = #{ <<"priv-wallet">> => ar_wallet:new() },
    Committed = hb_message:commit(
        #{ <<"body">> => <<"public-key-hmac">> }, Opts,
        #{
            <<"type">> => <<"hmac-sha256">>,
            <<"keyid">> => <<"publickey:", (base64:encode(Pub))/binary>>
        }
    ),
    ?assertNot(hb_message:verify(Committed, all, Opts)).

%% @doc HTTPSig rejects weak moduli, including zero-padded keys.
rsa_minimum_modulus_test() ->
    lists:foreach(
        fun(Bits) ->
            {[_, Pub], [_, Pub, Priv | _]} = crypto:generate_key(rsa, {Bits, 65537}),
            lists:foreach(
                fun(Key) ->
                    Wallet = {{{rsa, 65537}, Priv, Key}, {{rsa, 65537}, Key}},
                    Opts = #{ <<"priv-wallet">> => Wallet },
                    Data = <<"rsa-size">>,
                    Signature = ar_wallet:sign(Wallet, Data),
                    ?assert(ar_wallet:verify({{rsa, 65537}, Key}, Data, Signature)),
                    Signed = hb_message:commit(#{ <<"body">> => Data }, Opts),
                    ?assertEqual(Bits >= 2048, hb_message:verify(Signed, all, Opts))
                end,
                [Pub, <<0:4096, Pub/binary>>]
            )
        end,
        [1536, 2048]
    ).

%% @doc Ensure that we can validate a signature on an extremely large and complex
%% message that is sent over HTTP, signed with the codec.
validate_large_message_from_http_test() ->
    Node = hb_http_server:start_node(Opts = #{
        <<"force-signed">> => true,
        <<"commitment-device">> => <<"httpsig@1.0">>,
        extra =>
            [
                [
                    [
                        #{
                            <<"n">> => N,
                            <<"m">> => M,
                            <<"o">> => O
                        }
                    ||
                        O <- lists:seq(1, 3)
                    ]
                ||
                    M <- lists:seq(1, 3)
                ]
            ||
                N <- lists:seq(1, 3)
            ]
    }),
    {ok, Res} = hb_http:get(Node, <<"/~meta@1.0/info">>, Opts),
    Signers = hb_message:signers(Res, Opts),
    ?event_debug({received, {signers, Signers}, {res, Res}}),
    ?assert(length(Signers) == 1),
    ?assert(hb_message:verify(Res, Signers, Opts)),
    ?event_debug({sig_verifies, Signers}),
    ?assert(hb_message:verify(Res, all, Opts)),
    ?event_debug({hmac_verifies, <<"hmac-sha256">>}),
    {ok, _, #{ <<"committed">> := HashpathCommitted }} =
        hb_message:commitment(
            #{ <<"committer">> => hd(Signers) },
            Res,
            Opts
        ),
    ?assertEqual([<<"hashpath">>], HashpathCommitted).

committed_id_test() ->
    Msg = #{ <<"basic">> => <<"value">> },
    Opts = #{ <<"priv-wallet">> => hb:wallet() },
    Signed = hb_message:commit(Msg, Opts),
    ?assert(hb_message:verify(Signed, all, Opts)),
    ?event_debug({signed_msg, Signed}),
    UnsignedID = hb_message:id(Signed, none),
    SignedID = hb_message:id(Signed, all),
    ?event_debug({ids, {unsigned_id, UnsignedID}, {signed_id, SignedID}}),
    ?assertNotEqual(UnsignedID, SignedID).

commit_secret_key_test() ->
    Msg = #{ <<"basic">> => <<"value">> },
    Opts = #{ <<"priv-wallet">> => hb:wallet() },
    CommittedMsg =
        hb_message:commit(
            Msg,
            Opts,
            #{
                <<"type">> => <<"hmac-sha256">>,
                <<"priv">> => #{ <<"secret">> => <<"test-secret">> },
                <<"commitment-device">> => <<"httpsig@1.0">>,
                <<"scheme">> => <<"secret">>
            }
        ),
    ?event_debug({committed_msg, CommittedMsg}),
    Committers = hb_message:signers(CommittedMsg, #{}),
    ?assert(length(Committers) == 1),
    ?event_debug({committers, Committers}),
    ?assert(
        hb_message:verify(
            CommittedMsg,
            #{
                <<"committers">> => Committers,
                <<"priv">> => #{ <<"secret">> => <<"test-secret">> }
            },
            #{}
        )
    ),
    ?assertNot(
        hb_message:verify(
            CommittedMsg,
            #{
                <<"committers">> => Committers,
                <<"priv">> => #{ <<"secret">> => <<"bad-secret">> }
            },
            #{}
        )
    ).

multicommitted_id_test() ->
    Msg = #{ <<"basic">> => <<"value">> },
    Signed1 = hb_message:commit(Msg, #{ <<"priv-wallet">> => Wallet1 = ar_wallet:new() }),
    Signed2 = hb_message:commit(Signed1, #{ <<"priv-wallet">> => Wallet2 = ar_wallet:new() }),
    Addr1 = hb_util:human_id(ar_wallet:to_address(Wallet1)),
    Addr2 = hb_util:human_id(ar_wallet:to_address(Wallet2)),
    ?event_debug({signed_msg, Signed2}),
    UnsignedID = hb_message:id(Signed2, none),
    SignedID = hb_message:id(Signed2, all),
    ?event_debug({ids, {unsigned_id, UnsignedID}, {signed_id, SignedID}}),
    ?assertNotEqual(UnsignedID, SignedID),
    ?assert(hb_message:verify(Signed2, [])),
    ?assert(hb_message:verify(Signed2, [Addr1])),
    ?assert(hb_message:verify(Signed2, [Addr2])),
    ?assert(hb_message:verify(Signed2, [Addr1, Addr2])),
    ?assert(hb_message:verify(Signed2, [Addr2, Addr1])),
    ?assert(hb_message:verify(Signed2, all)).

%% @doc Test that we can sign and verify a message with a link. We use 
sign_and_verify_link_test() ->
    Msg = #{
        <<"normal">> => <<"typical-value">>,
        <<"untyped">> => #{ <<"inner-untyped">> => <<"inner-value">> },
        <<"typed">> => #{ <<"inner-typed">> => 123 }
    },
    Opts = #{ <<"priv-wallet">> => hb:wallet() },
    NormMsg = hb_message:convert(Msg, <<"structured@1.0">>, #{}),
    ?event_debug({msg, NormMsg}),
    Signed = hb_message:commit(NormMsg, Opts),
    ?event_debug({signed_msg, Signed}),
    ?assert(hb_message:verify(Signed, Opts)).
