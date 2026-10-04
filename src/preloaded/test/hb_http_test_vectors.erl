%%% @doc A battery of test vectors for serving messages between nodes over
%%% HTTP. Each message is written to the cache of an isolated primary node, then
%%% read back over three paths -- directly with `hb_http', through a
%%% `hb_store_remote_node' store, and from a secondary node that downloaded and
%%% cached it -- with every codec and both `accept-bundle' settings. Each read
%%% is checked against the message that was written: its values and types, its
%%% signatures and its IDs.
%%%
%%% Run a single case with
%%% `eunit:test(hb_http_test_vectors:run(Name, Path, Transport))'.
-module(hb_http_test_vectors).
-export([run/3]).
-include_lib("eunit/include/eunit.hrl").

%% @doc The messages that the primary node serves. A message given as a
%% function is built with the primary's options, so that it can be signed.
messages() ->
    [
        {"basic", #{ <<"hello">> => <<"world">> }},
        {"body", #{ <<"body">> => <<"hello">> }},
        {"empty body", #{ <<"body">> => <<>> }},
        {"empty message", #{}},
        {"empty child", #{ <<"child">> => #{} }},
        {"empty list", #{ <<"items">> => [] }},
        {"typed scalars", typed()},
        {"large integers",
            #{
                <<"positive">> => 9007199254740993,
                <<"negative">> => -9007199254740993
            }
        },
        {"binary body", #{ <<"body">> => <<0, 255, 1, 128>> }},
        {"escaped header", #{ <<"text">> => <<"a\nb\r\n\"c\"\\d">> }},
        {"edge whitespace", #{ <<"text">> => <<" \tvalue\t ">> }},
        {"unicode",
            #{ <<"text">> => <<"caf", 195, 169, 240, 159, 140, 141>> }
        },
        {"binary list", #{ <<"items">> => [<<"a">>, <<"b">>, <<>>] }},
        {"typed list", #{ <<"items">> => [1, 2.5, true, null, <<"x">>] }},
        {"root list", [1, <<"two">>, #{ <<"three">> => 3 }]},
        {"nested message",
            #{ <<"child">> => #{ <<"hello">> => <<"world">> } }
        },
        {"nested typed", #{ <<"child">> => typed() }},
        {"nested typed list",
            #{
                <<"items">> =>
                    [
                        [1, 2.5],
                        #{ <<"enabled">> => false },
                        [true, <<"x">>]
                    ]
            }
        },
        {"list of messages", #{ <<"items">> => [typed(), typed()] }},
        {"nested typed body", #{ <<"child">> => #{ <<"body">> => 42 } }},
        {"nested body and data",
            #{
                <<"child">> =>
                    #{
                        <<"body">> => <<"body bytes">>,
                        <<"data">> => <<"data bytes">>
                    }
            }
        },
        {"deep message",
            lists:foldl(
                fun(_, Msg) -> #{ <<"child">> => Msg } end,
                typed(),
                lists:seq(1, 6)
            )
        },
        {"wide message",
            maps:from_list([{hb_util:bin(N), N} || N <- lists:seq(1, 32)])
        },
        {"large body",
            #{ <<"body">> => binary:copy(<<"abcdefgh">>, 2048) }
        },
        {"large header", #{ <<"text">> => binary:copy(<<"x">>, 8192) }},
        {"reserved data keys",
            #{
                <<"signature">> => <<"data">>,
                <<"content-digest">> => <<"also data">>
            }
        },
        {"content type",
            #{
                <<"content-type">> => <<"text/plain">>,
                <<"body">> => <<"hello">>
            }
        },
        {"unsigned status",
            #{ <<"status">> => <<"pending">>, <<"value">> => 1 }
        },
        {"nested ans104",
            fun(Opts) ->
                #{ <<"child">> => signed(typed(), <<"ans104@1.0">>, Opts) }
            end
        },
        {"nested bundled ans104",
            fun(Opts) ->
                #{
                    <<"child">> =>
                        signed(nested(), bundle(<<"ans104@1.0">>), Opts)
                }
            end
        },
        {"double httpsig",
            fun(Opts) -> double(typed(), <<"httpsig@1.0">>, Opts) end
        },
        {"double bundled httpsig",
            fun(Opts) -> double(nested(), bundle(<<"httpsig@1.0">>), Opts) end
        },
        {"mixed signatures",
            fun(Opts) ->
                signed(
                    signed(typed(), <<"ans104@1.0">>, Opts),
                    <<"httpsig@1.0">>,
                    Opts
                )
            end
        },
        {"multiply signed child",
            fun(Opts) ->
                #{ <<"child">> => double(typed(), <<"httpsig@1.0">>, Opts) }
            end
        }
    ] ++
    [
        {"signed " ++ Name, fun(Opts) -> signed(nested(), Spec, Opts) end}
    ||
        {Name, Spec} <-
            [
                {"httpsig", <<"httpsig@1.0">>},
                {"bundled httpsig", bundle(<<"httpsig@1.0">>)},
                {"ans104", <<"ans104@1.0">>},
                {"bundled ans104", bundle(<<"ans104@1.0">>)},
                {"tx", <<"tx@1.0">>},
                {"bundled tx", bundle(<<"tx@1.0">>)}
            ]
    ] ++
    [
        {"signed " ++ Name ++ " ans104",
            fun(Opts) ->
                signed(
                    nested(),
                    #{ <<"device">> => <<"ans104@1.0">>, <<"type">> => Type },
                    Opts#{ <<"priv-wallet">> => ar_wallet:new(KeyType) }
                )
            end
        }
    ||
        {Name, Type, KeyType} <-
            [
                {"ed25519", <<"ed25519-sha512">>, {eddsa, ed25519}},
                {"ethereum", <<"ethereum">>, ethereum}
            ]
    ].

%% @doc The ways that a client reads a message from the primary node.
paths() -> [direct, remote, secondary].

%% @doc The transports: each way of asking for a codec, with every codec that
%% `hb_codec_test_vectors' tests, and both `accept-bundle' settings. The MIME
%% `accept' header also covers its precedence below a message's own
%% `content-type'.
transports() ->
    [
        {
            hb_util:list(Mode) ++ "=" ++ hb_util:list(Codec) ++
                " / accept-bundle=" ++ hb_util:list(Bundle),
            #{ mode => Mode, codec => Codec, bundle => Bundle }
        }
    ||
        Mode <- ['require-codec', 'accept-codec', accept],
        Codec <-
            [
                <<"httpsig@1.0">>,
                <<"json@1.0">>,
                <<"ans104@1.0">>,
                <<"flat@1.0">>,
                <<"structured@1.0">>,
                <<"tx@1.0">>
            ],
        Bundle <- [false, true]
    ].

%% @doc The combinations that a codec cannot represent by design, each with
%% its reason. They are not generated as tests.
exceptions() ->
    [
        {[Name || {Name, _} <- messages()], <<"flat@1.0">>, [false, true],
            "Flat text does not escape newlines or ': ' in keys and values."},
        {[Name || {Name, _} <- messages()], <<"structured@1.0">>, [false, true],
            "Structured messages have no binary wire format."},
        {
            [
                "double httpsig",
                "double bundled httpsig",
                "mixed signatures",
                "signed httpsig",
                "signed bundled httpsig",
                "signed ans104",
                "signed bundled ans104",
                "signed ed25519 ans104",
                "signed ethereum ans104"
            ],
            <<"tx@1.0">>,
            [false, true],
            "A transaction carries one native root signature, not foreign ones."
        },
        {["empty child"], <<"flat@1.0">>, [true],
            "Flat paths cannot represent an empty nested map."},
        {
            [
                "double httpsig",
                "double bundled httpsig",
                "mixed signatures",
                "signed httpsig",
                "signed bundled httpsig",
                "signed tx",
                "signed bundled tx"
            ],
            <<"ans104@1.0">>,
            [false, true],
            "An ANS-104 item carries one native root signature, not foreign ones."
        }
    ].

typed() ->
    #{
        <<"integer">> => 42,
        <<"float">> => 1.5,
        <<"boolean">> => true,
        <<"atom">> => null
    }.

nested() -> #{ <<"body">> => <<"payload">>, <<"child">> => typed() }.

bundle(Codec) -> #{ <<"device">> => Codec, <<"bundle">> => true }.

signed(Msg, Spec, Opts) -> hb_message:commit(Msg, Opts, Spec).

%% @doc Sign a message with two wallets.
double(Msg, Spec, Opts) ->
    Result =
        signed(
            signed(Msg, Spec, Opts),
            Spec,
            Opts#{
                <<"priv-wallet">> => maps:get(<<"priv-second-wallet">>, Opts)
            }
        ),
    ?assertEqual(2, length(hb_message:signers(Result, Opts))),
    Result.

suite_test_() -> suite(messages(), paths(), transports()).

%% @doc Generate one named case of the suite, to reproduce it alone.
run(Name, Path, Transport) ->
    {Name, _} = Message = lists:keyfind(Name, 1, messages()),
    {Transport, Spec} = Selection = lists:keyfind(Transport, 1, transports()),
    true = lists:member(Path, paths()),
    false = excluded(Name, Spec),
    suite([Message], [Path], [Selection]).

%% @doc Generate the tests: one primary node holds every message, and each test
%% reads one message over one path and transport with fresh client stores.
suite(Messages, Paths, Transports) ->
    {setup,
        fun() -> primary(Messages) end,
        fun stop_primary/1,
        fun({Host, _PrimaryOpts, Prepared}) ->
            [{foreach, Setup, Reset, Tests}] =
                hb_test_utils:suite_with_opts(
                    [
                        {
                            Name,
                            Name ++ " / " ++ hb_util:list(Path) ++ " / " ++ Desc,
                            fun(ClientOpts) ->
                                {ok, Expected, ID} = Preparation,
                                ?assertEqual(
                                    {error, not_found},
                                    hb_cache:read(ID, ClientOpts)
                                ),
                                exercise(
                                    Path,
                                    Host,
                                    ID,
                                    Expected,
                                    Transport,
                                    ClientOpts
                                )
                            end
                        }
                    ||
                        {Name, Preparation} <- Prepared,
                        Path <- Paths,
                        {Desc, Transport} <- Transports,
                        not excluded(Name, Transport)
                    ],
                    [
                        #{
                            name => isolated,
                            desc => "HTTP vectors",
                            parallel => false,
                            timeout => 30,
                            opts => options()
                        }
                    ]
                ),
            % The suite helper resets each test's stores; they are also stopped,
            % so that their volatile tables are released.
            {foreach,
                Setup,
                fun(Opts) ->
                    try Reset(Opts)
                    after hb_store:stop(maps:get(<<"store">>, Opts))
                    end
                end,
                Tests
            }
        end
    }.

excluded(Name, #{ codec := Codec, bundle := Bundle }) ->
    lists:any(
        fun({Names, ExcludedCodec, Bundles, _Reason}) ->
            ExcludedCodec == Codec
                andalso lists:member(Name, Names)
                andalso lists:member(Bundle, Bundles)
        end,
        exceptions()
    ).

%% @doc Options for an isolated node or client: a fresh volatile store, no
%% hooks or uploads, and an ephemeral port.
options() ->
    #{
        <<"store">> => hb_test_utils:test_store(hb_store_volatile),
        <<"on">> => #{},
        <<"port">> => 0,
        <<"tls">> => false,
        <<"protocol">> => http2,
        <<"http-client">> => gun,
        <<"http-redirects">> => 0,
        <<"http-retry">> => 0,
        <<"http-client-send-timeout">> => 5000,
        <<"http-client-connect-timeout">> => 5000,
        <<"generate-index">> => false,
        <<"num-acceptors">> => 1,
        <<"prometheus">> => false,
        <<"process-sampler">> => false,
        <<"system-monitor">> => false
    }.

%% @doc Start the primary node and write each message to its cache. A message
%% that fails to build or write becomes a failing test, not a failed setup.
primary(Messages) ->
    Opts =
        (options())#{
            <<"priv-wallet">> => ar_wallet:new(),
            <<"priv-second-wallet">> => ar_wallet:new()
        },
    hb_store:start(maps:get(<<"store">>, Opts)),
    Host = hb_http_server:start_node(Opts),
    Prepared =
        [
            {Name, prepare(Message, Opts)}
        ||
            {Name, Message} <- Messages
        ],
    {Host, Opts, Prepared}.

prepare(Message, Opts) ->
    try
        Msg =
            case is_function(Message, 1) of
                true -> Message(Opts);
                false -> Message
            end,
        ?assertEqual(true, hb_message:deep_verify(Msg, Opts)),
        {ok, _} = hb_cache:write(Msg, Opts),
        {ok, Msg, hb_message:id(Msg, all, Opts)}
    catch Class:Reason:Stacktrace -> {error, {Class, Reason, Stacktrace}}
    end.

stop_primary({_Host, Opts, _Prepared}) -> stop_node(Opts).

stop_node(Opts) ->
    cowboy:stop_listener(
        hb_util:human_id(
            ar_wallet:to_address(maps:get(<<"priv-wallet">>, Opts))
        )
    ),
    hb_store:stop(maps:get(<<"store">>, Opts)).

%% @doc Read the message over a path and check it against the message that was
%% written, then check the codec of the reply on the wire.
exercise(direct, Host, ID, Expected, Transport, ClientOpts) ->
    Actual = download(Host, ID, Expected, Transport, ClientOpts),
    validate(Expected, Actual, ClientOpts),
    check_wire(Host, wire_request(ID, Transport), Expected, Transport);
exercise(remote, Host, ID, Expected, Transport, ClientOpts) ->
    Store = maps:get(<<"store">>, ClientOpts),
    Remote =
        ClientOpts#{
            <<"store-module">> => hb_store_remote_node,
            <<"node">> =>
                #{
                    <<"uri">> =>
                        <<
                            Host/binary,
                            "~cache@1.0/read?",
                            (query(Transport))/binary
                        >>,
                    <<"opts">> => #{}
                },
            <<"store">> => Store,
            <<"local-store">> => Store,
            <<"access">> => [<<"read">>]
        },
    ReadOpts = ClientOpts#{ <<"store">> => [Store, Remote] },
    {ok, Received} = hb_cache:read(ID, ReadOpts),
    Actual = hb_cache:ensure_all_loaded(Received, ReadOpts),
    validate(Expected, Actual, ReadOpts),
    check_wire(
        Host,
        #{
            path => <<"/~cache@1.0/read?", (query(Transport))/binary>>,
            headers => #{ <<"read">> => ID }
        },
        Expected,
        Transport
    );
exercise(secondary, Host, ID, Expected, Transport, ClientOpts) ->
    SecondaryOpts = (options())#{ <<"priv-wallet">> => ar_wallet:new() },
    SecondaryHost = hb_http_server:start_node(SecondaryOpts),
    try
        ?assertEqual({error, not_found}, hb_cache:read(ID, SecondaryOpts)),
        Downloaded = download(Host, ID, Expected, Transport, SecondaryOpts),
        validate(Expected, Downloaded, SecondaryOpts),
        {ok, _} = hb_cache:write(Downloaded, SecondaryOpts),
        {ok, Cached} = hb_cache:read(ID, SecondaryOpts),
        validate(
            Expected,
            hb_cache:ensure_all_loaded(Cached, SecondaryOpts),
            SecondaryOpts
        ),
        % The secondary has only its local store, so the client's read cannot
        % reach the primary.
        Actual = download(SecondaryHost, ID, Expected, Transport, ClientOpts),
        validate(Expected, Actual, ClientOpts),
        check_wire(
            SecondaryHost,
            wire_request(ID, Transport),
            Expected,
            Transport
        )
    after stop_node(SecondaryOpts)
    end.

%% @doc The transport as a query string. A remote store builds its own request
%% headers, so its transport is given in the URI.
query(Transport) ->
    uri_string:compose_query(maps:to_list(headers(Transport))).

%% @doc The request headers that ask for the transport's codec. Lazy links in
%% the reply are loaded with `hb_http''s usual peer stores.
headers(#{ mode := Mode, codec := Codec, bundle := Bundle }) ->
    #{
        hb_util:bin(Mode) =>
            case Mode of
                accept -> <<"application/", Codec/binary>>;
                _ -> Codec
            end,
        <<"accept-bundle">> => hb_util:bin(Bundle)
    }.

download(Host, ID, Expected, Transport, Opts) ->
    {ok, Received} =
        hb_http:get(
            Host,
            (headers(Transport))#{ <<"path">> => <<"/", ID/binary>> },
            Opts
        ),
    Loaded = hb_cache:ensure_all_loaded(Received, Opts),
    ?assertEqual(true, hb_message:deep_verify(Loaded, Opts)),
    payload(Expected, Loaded, Opts).

%% @doc Remove the keys and commitments that the reply adds, keeping any that
%% the message itself holds.
payload(Expected, Received, Opts) when is_map(Expected), is_map(Received) ->
    WithoutReceipt =
        hb_message:without_commitments(
            #{ <<"committed">> => [<<"hashpath">>] },
            Received,
            Opts
        ),
    {ok, Committed} = hb_message:with_only_committed(WithoutReceipt, Opts),
    % A codec may add an unsigned commitment over the reply. It verified above;
    % keep only the signed commitments and those of the message itself.
    ExpectedCommitments = maps:get(<<"commitments">>, Expected, #{}),
    Payload =
        Committed#{
            <<"commitments">> =>
                maps:filter(
                    fun(ID, Commitment) ->
                        maps:is_key(<<"committer">>, Commitment)
                            orelse maps:is_key(ID, ExpectedCommitments)
                    end,
                    maps:get(<<"commitments">>, Committed, #{})
                )
        },
    maps:without(
        [Key || Key <- response_keys(), not maps:is_key(Key, Expected)],
        Payload
    );
payload(_Expected, Received, _Opts) -> Received.

%% @doc The keys that a reply adds, unless the message holds them itself.
response_keys() ->
    [
        <<"status">>,
        <<"hashpath">>,
        <<"date">>,
        <<"server">>,
        <<"access-control-allow-origin">>,
        <<"access-control-allow-methods">>,
        <<"access-control-expose-headers">>
    ].

%% @doc Check a read message against the message that was written: exact values
%% and types, a strict match, signatures, and IDs.
validate(Expected, Actual, Opts) ->
    ?assertEqual(content(Expected), content(Actual)),
    case is_map(Expected) of
        true ->
            ?assertEqual(
                true,
                hb_message:match(Expected, Actual, strict, Opts)
            );
        false -> ok
    end,
    ?assertEqual(true, hb_message:deep_verify(Actual, Opts)),
    identities(Expected, Actual, Opts).

%% @doc A message's values, without its commitments or private keys.
content(Msg) when is_map(Msg) ->
    maps:map(
        fun(_, Value) -> content(Value) end,
        maps:without([<<"commitments">>], hb_private:reset(Msg))
    );
content(List) when is_list(List) -> [content(Value) || Value <- List];
content(Value) -> Value.

%% @doc Check the signed and unsigned IDs of a message and of each message it
%% holds, so that a message without commitments cannot pass by verifying
%% nothing.
identities(Expected, Actual, Opts) when is_map(Expected) ->
    ?assertEqual(signed_ids(Expected), signed_ids(Actual)),
    lists:foreach(
        fun(Kind) ->
            ?assertEqual(
                hb_message:id(Expected, Kind, Opts),
                hb_message:id(Actual, Kind, Opts)
            )
        end,
        [unsigned, signed]
    ),
    maps:foreach(
        fun(Key, Value) -> identities(Value, maps:get(Key, Actual), Opts) end,
        maps:without([<<"commitments">>], hb_private:reset(Expected))
    );
identities(Expected, Actual, Opts) when is_list(Expected) ->
    ?assertEqual(
        hb_message:id(Expected, unsigned, Opts),
        hb_message:id(Actual, unsigned, Opts)
    ),
    lists:foreach(
        fun({ExpectedValue, ActualValue}) ->
            identities(ExpectedValue, ActualValue, Opts)
        end,
        lists:zip(Expected, Actual)
    );
identities(_Expected, _Actual, _Opts) -> ok.

signed_ids(Msg) ->
    lists:sort(
        [
            ID
        ||
            {ID, Commitment} <-
                maps:to_list(maps:get(<<"commitments">>, Msg, #{})),
            maps:is_key(<<"committer">>, Commitment)
        ]
    ).

wire_request(ID, Transport) ->
    #{ path => <<"/", ID/binary>>, headers => headers(Transport) }.

%% @doc Check the codec of the reply on the wire, which `hb_http' does not
%% return. A request from a fresh client means that a client decoding the reply
%% in another codec cannot hide a wrong negotiation.
check_wire(Host, Request, Expected, #{ codec := Codec, mode := Mode }) ->
    Opts = options(),
    try
        {ok, 200, Headers, Body} =
            hb_http_client:request(
                Request#{ peer => Host, method => <<"GET">>, body => <<>> },
                Opts
            ),
        % A message's own `content-type' takes precedence over a codec that
        % the client prefers, but not over one that it requires.
        Wanted =
            case Mode =/= 'require-codec'
                    andalso is_map(Expected)
                    andalso maps:is_key(<<"content-type">>, Expected) of
                true -> <<"httpsig@1.0">>;
                false -> Codec
            end,
        ?assertEqual(
            Wanted,
            proplists:get_value(<<"codec-device">>, Headers, <<"httpsig@1.0">>)
        ),
        % A client can decode an invalid ANS-104 body as HTTPSig, so the body
        % is also decoded as ANS-104 directly.
        case Wanted of
            <<"ans104@1.0">> -> ar_bundles:deserialize(Body);
            _ -> ok
        end
    after hb_store:stop(maps:get(<<"store">>, Opts))
    end.
