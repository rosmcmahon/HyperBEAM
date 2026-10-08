%%% @doc `shepherd-feed@1.0' reports the weave items a node takes in to a
%%% Shepherd content-moderation server. Each report is a JSON object whose
%%% `items' are GraphQL-shaped transaction nodes (`id', `data/size',
%%% `data/type', `tags', `owner/address' and `owner/key'), POSTed to the node
%%% option `shepherd-feed-url' with `shepherd-feed-token' as a bearer token.
%%% Every field is read from an item the node has verified, from its signed
%%% `ans104@1.0' or `tx@1.0' commitment: `owner/address' is the committer,
%%% which is native to the signer's chain for Ethereum and Solana signers, as
%%% in GraphQL, and `owner/key' is the signer's base64url public key.
%%% `data/type' is omitted when the item has no UTF-8 `content-type', and tags
%%% that are not UTF-8 are omitted.
%%%
%%% Sources:
%%% ```
%%%     upload:  `response' hook. Items accepted by `~bundler@1.0', read back
%%%              from the cache that the bundler writes them to before it
%%%              responds.
%%%     copycat: `cache-write' hook. Items written at a weave offset, as
%%%              copycat writes them. A node that runs no copycat reports
%%%              none.
%%% '''
%%% Both pass items to a batching process per node and feed URL, and return
%%% the hook request unchanged. Their failures are logged and dropped: a failed
%%% `response' hook fails the upload's response, and a failed `cache-write'
%%% hook fails the cache write. A report that the node's HTTP client cannot
%%% deliver after its retries is dropped.
%%%
%%% `install' is a `start' hook that registers the sources. A node's `on'
%%% option replaces the default hooks, so `install' rebuilds them: the defaults,
%%% overridden by the node's own hooks, with the sources appended. Without
%%% `shepherd-feed-url' it rebuilds the hooks and appends no sources.
%%% ```
%%%     "on": { "start": { "device": "shepherd-feed@1.0", "path": "install" } }
%%% '''
-module(dev_shepherd_feed).
-export([install/3, upload/3, copycat/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%%% The largest number of items in one report.
-define(PAGE_ITEMS, 100).
%%% The largest report body, in bytes.
-define(PAGE_BYTES, 200 * 1024).
%%% The longest that an item waits for its report to fill, in milliseconds.
-define(FLUSH_MS, 2000).
%%% Items are dropped while the batching process holds this many messages.
-define(MAX_PENDING, 50000).
%%% The commitment devices of weave items.
-define(DEVICES, [<<"ans104@1.0">>, <<"tx@1.0">>]).
%%% The keys of an item's TABM that are not tags.
-define(NOT_TAGS, [
    <<"commitments">>, <<"priv">>, <<"ao-types">>, <<"ao-data-key">>,
    <<"data">>, <<"anchor">>, <<"target">>, <<"format">>, <<"quantity">>,
    <<"reward">>, <<"data_root">>, <<"data_size">>
]).

%% @doc Rebuild the node's hooks from the defaults and its own hooks, with the
%% feed's sources appended when `shepherd-feed-url' is set.
install(_Base, Req = #{ <<"body">> := NodeMsg }, Opts) ->
    Defaults =
        hb_maps:get(<<"on">>, hb_opts:default_message_with_env(), #{}, Opts),
    Configured = hb_maps:get(<<"on">>, NodeMsg, #{}, Opts),
    On = hb_maps:merge(Defaults, Configured, Opts),
    Sources =
        case hb_maps:is_key(<<"shepherd-feed-url">>, NodeMsg, Opts) of
            false -> [];
            true ->
                [
                    {<<"response">>, <<"upload">>},
                    {<<"cache-write">>, <<"copycat">>}
                ]
        end,
    WithSources = lists:foldl(fun add_source/2, On, Sources),
    {ok, Req#{ <<"body">> => NodeMsg#{ <<"on">> => WithSources } }}.

%% @doc Append a feed handler to a hook, unless the hook already has it.
add_source({Hook, Path}, On) ->
    Handler = #{ <<"device">> => <<"shepherd-feed@1.0">>, <<"path">> => Path },
    Handlers = hb_hook:find(Hook, #{ <<"on">> => On }),
    case lists:member(Handler, Handlers) of
        true -> On;
        false -> On#{ Hook => Handlers ++ [Handler] }
    end.

%% @doc Report the item that a `response' hook request shows the bundler
%% accepted.
upload(_Base, Req, Opts) ->
    guard(
        fun() ->
            Request = hb_maps:get(<<"request">>, Req, #{}, Opts),
            Res = hb_maps:get(<<"body">>, Req, #{}, Opts),
            case is_upload(Request, Res, Opts) of
                true ->
                    ID = hb_maps:get(<<"id">>, Res, undefined, Opts),
                    cast({upload, ID}, Opts);
                false ->
                    ok
            end
        end
    ),
    {ok, Req}.

%% @doc Whether a request to a bundler path resulted in an accepted item: an
%% `id' and `timestamp' with status 200.
is_upload(Request, Res, Opts) when is_map(Request), is_map(Res) ->
    Path = hb_util:bin(hb_maps:get(<<"path">>, Request, <<>>, Opts)),
    hb_maps:get(<<"status">>, Res, 0, Opts) =:= 200 andalso
        hb_maps:is_key(<<"id">>, Res, Opts) andalso
        hb_maps:is_key(<<"timestamp">>, Res, Opts) andalso
        binary:match(Path, <<"bundler@1.0">>) =/= nomatch;
is_upload(_Request, _Res, _Opts) ->
    false.

%% @doc Report the signed IDs of an item that the cache writes at a weave
%% offset. As for `match@1.0', only the kernel's `cache-write' hook is served.
copycat(_Base, Req, Opts) ->
    guard(
        fun() ->
            Body = hb_maps:get(<<"body">>, Req, #{}, Opts),
            Caller = hb_private:get(<<"hook-caller">>, Req, Opts),
            case hb_private:get(<<"offset">>, Body, -1, Opts) of
                Offset when Caller =:= <<"kernel">>, is_integer(Offset),
                        Offset >= 0 ->
                    lists:foreach(
                        fun(ID) -> report(ID, Body, Opts) end,
                        hb_maps:get(<<"signed-ids">>, Req, [], Opts)
                    );
                _ ->
                    ok
            end
        end
    ),
    {ok, Req}.

%% @doc Queue the report of one ID of a TABM item, if it is a weave item.
report(ID, TABM, Opts) ->
    case gql_node(ID, TABM, Opts) of
        skip -> ok;
        Node -> cast({node, Node}, Opts)
    end.

%% @doc Run a source, logging rather than raising its failure.
guard(Fun) ->
    try Fun()
    catch Class:Reason:Stacktrace ->
        ?event(warning,
            {shepherd_feed_source_failed,
                {class, Class},
                {reason, Reason},
                {stacktrace, {trace, Stacktrace}}
            }
        )
    end.

%% @doc The GraphQL `transactions' node of one ID of a TABM item, without
%% `block' and `parent', or `skip' if the ID is not of a weave item's signed
%% commitment.
gql_node(ID, TABM, Opts) ->
    Commitments = hb_maps:get(<<"commitments">>, TABM, #{}, Opts),
    Commitment = hb_maps:get(ID, Commitments, #{}, Opts),
    Device = hb_maps:get(<<"commitment-device">>, Commitment, none, Opts),
    maybe
        true ?= lists:member(Device, ?DEVICES),
        {ok, Owner} ?= hb_maps:find(<<"committer">>, Commitment, Opts),
        {ok, KeyID} ?= hb_maps:find(<<"keyid">>, Commitment, Opts),
        Size = integer_to_binary(data_size(TABM, Commitment, Opts)),
        Type = text(hb_maps:get(<<"content-type">>, TABM, not_found, Opts)),
        #{
            <<"id">> => ID,
            <<"data">> =>
                case Type of
                    not_text -> #{ <<"size">> => Size };
                    _ -> #{ <<"size">> => Size, <<"type">> => Type }
                end,
            <<"tags">> => tags(TABM, Commitment, Opts),
            <<"owner">> =>
                #{
                    <<"address">> => Owner,
                    <<"key">> => hb_util:remove_scheme_prefix(KeyID)
                }
        }
    else
        _ -> skip
    end.

%% @doc The size of an item's data. Items carry their data; transaction
%% headers carry `data_size' instead.
data_size(TABM, Commitment, Opts) ->
    DataKey = hb_maps:get(<<"ao-data-key">>, TABM, <<"data">>, Opts),
    case hb_maps:get(DataKey, TABM, not_found, Opts) of
        Data when is_binary(Data) -> byte_size(Data);
        _ ->
            hb_util:int(
                hb_maps:get(
                    <<"data_size">>,
                    TABM,
                    hb_maps:get(<<"field-data_size">>, Commitment, 0, Opts),
                    Opts
                )
            )
    end.

%% @doc An item's tags that JSON can carry. Exact tag names and order are in
%% the commitment's `original-tags' unless every tag was already a normalized
%% key of the item.
tags(TABM, Commitment, Opts) ->
    Pairs =
        case hb_maps:find(<<"original-tags">>, Commitment, Opts) of
            {ok, Original} ->
                [
                    {
                        hb_maps:get(<<"name">>, Tag, not_found, Opts),
                        hb_maps:get(<<"value">>, Tag, not_found, Opts)
                    }
                ||
                    Tag <- hb_util:message_to_ordered_list(Original, Opts)
                ];
            error ->
                [
                    {Name, Value}
                ||
                    {Name, Value} <- hb_maps:to_list(TABM, Opts),
                    not lists:member(Name, ?NOT_TAGS)
                ]
        end,
    [
        #{ <<"name">> => Name, <<"value">> => Value }
    ||
        {Name, Value} <- Pairs,
        text(Name) =/= not_text,
        text(Value) =/= not_text
    ].

%% @doc A value as JSON text: the value if it is a valid UTF-8 binary,
%% otherwise `not_text'.
text(Bin) when is_binary(Bin) ->
    case unicode:characters_to_binary(Bin) of
        Bin -> Bin;
        _ -> not_text
    end;
text(_) ->
    not_text.

%%% Batching: one report per page of up to `PAGE_ITEMS' items, sent at most
%%% `FLUSH_MS' after the page's first item.

%% @doc Send a message to the batching process, dropping it if the process is
%% too far behind.
cast(Msg, Opts) ->
    case batcher(Opts) of
        not_configured -> ok;
        Batcher ->
            case erlang:process_info(Batcher, message_queue_len) of
                {message_queue_len, Len} when Len >= ?MAX_PENDING ->
                    ?event(warning, {shepherd_feed_full, {pending, Len}});
                _ ->
                    Batcher ! Msg
            end
    end.

%% @doc The batching process of this node and feed URL, started on first use.
batcher(Opts) ->
    case hb_opts:get(<<"shepherd-feed-url">>, not_configured, Opts) of
        not_configured -> not_configured;
        URL ->
            Server = hb_opts:get(<<"http-server">>, no_server, Opts),
            hb_name:singleton(
                {shepherd_feed, Server, URL},
                fun() -> collect(URL, Opts, [], 0, 0) end
            )
    end.

%% @doc Collect nodes into a page, in reverse order.
collect(URL, Opts, Page, Count, Bytes) ->
    receive
        {upload, ID} ->
            case upload_node(ID, Opts) of
                skip -> collect(URL, Opts, Page, Count, Bytes);
                Node -> add(Node, URL, Opts, Page, Count, Bytes)
            end;
        {node, Node} ->
            add(Node, URL, Opts, Page, Count, Bytes);
        flush ->
            send(URL, Page, Opts),
            collect(URL, Opts, [], 0, 0)
    end.

%% @doc Read an uploaded item from the cache and build its node.
upload_node(ID, Opts) ->
    try
        {ok, Item} = hb_cache:read(ID, Opts),
        TABM =
            hb_message:convert(
                hb_cache:ensure_all_loaded(Item, Opts),
                tabm,
                <<"structured@1.0">>,
                Opts
            ),
        gql_node(ID, TABM, Opts)
    catch Class:Reason ->
        ?event(warning,
            {shepherd_feed_upload_unread,
                {id, ID},
                {class, Class},
                {reason, Reason}
            }
        ),
        skip
    end.

%% @doc Add a node to the page, first sending the page if the node's JSON would
%% take it past `PAGE_BYTES', and sending it once it is full.
add(Node, URL, Opts, Page, Count, Bytes) ->
    Size = byte_size(hb_json:encode(Node)) + 1,
    case Count > 0 andalso Bytes + Size > ?PAGE_BYTES of
        true ->
            send(URL, Page, Opts),
            add(Node, URL, Opts, [], 0, 0);
        false ->
            case Count of
                0 -> erlang:send_after(?FLUSH_MS, self(), flush);
                _ -> ok
            end,
            case Count + 1 of
                ?PAGE_ITEMS ->
                    send(URL, [Node | Page], Opts),
                    collect(URL, Opts, [], 0, 0);
                NewCount ->
                    collect(URL, Opts, [Node | Page], NewCount, Bytes + Size)
            end
    end.

%% @doc POST a page to the feed URL as JSON, as a request to an explicit URL,
%% so that the node's HTTP client and its TLS and retry settings apply. The
%% bearer token is sent only when one is set: an `authorization' value that
%% cannot be a header would turn the request into a multipart body.
send(_URL, [], _Opts) ->
    ok;
send(URL, Page, Opts) ->
    Authorization =
        case hb_util:bin(hb_opts:get(<<"shepherd-feed-token">>, <<>>, Opts)) of
            <<>> -> #{};
            Token -> #{ <<"authorization">> => <<"Bearer ", Token/binary>> }
        end,
    Report =
        Authorization#{
            <<"method">> => <<"POST">>,
            <<"path">> => URL,
            <<"content-type">> => <<"application/json">>,
            <<"body">> =>
                hb_json:encode(#{ <<"items">> => lists:reverse(Page) })
        },
    try hb_http:request(Report, Opts) of
        {ok, _Res} ->
            ok;
        Other ->
            ?event(warning,
                {shepherd_feed_report_dropped,
                    {items, length(Page)},
                    {response, Other}
                }
            )
    catch Class:Reason ->
        ?event(warning,
            {shepherd_feed_report_failed,
                {items, length(Page)},
                {class, Class},
                {reason, Reason}
            }
        )
    end.

%%% Tests

%% @doc Start a node that sends the caller each request it receives.
start_receiver() ->
    Self = self(),
    hb_http_server:start_node(
        #{
            <<"priv-wallet">> => ar_wallet:new(),
            <<"store">> => hb_test_utils:test_store(),
            <<"on">> =>
                #{
                    <<"request">> =>
                        #{
                            <<"device">> =>
                                #{
                                    <<"request">> =>
                                        fun(_, Req, Opts) ->
                                            Request =
                                                hb_maps:get(
                                                    <<"request">>,
                                                    Req,
                                                    #{},
                                                    Opts
                                                ),
                                            Self ! {received, Request},
                                            {ok, Req}
                                        end
                                }
                        }
                }
        }
    ).

%% @doc Wait for a report, returning its authorization and the fields of its
%% items as the receiving node parsed them.
receive_report() ->
    receive
        {received, Request} ->
            {
                hb_maps:get(<<"authorization">>, Request, undefined, #{}),
                [
                    item_fields(Item)
                ||
                    Item <- hb_maps:get(<<"items">>, Request, [], #{})
                ]
            }
    after 10000 -> timeout
    end.

%% @doc The fields of a reported item.
item_fields(Item) ->
    Data = hb_maps:get(<<"data">>, Item, #{}, #{}),
    Owner = hb_maps:get(<<"owner">>, Item, #{}, #{}),
    #{
        id => hb_maps:get(<<"id">>, Item, undefined, #{}),
        size => hb_maps:get(<<"size">>, Data, undefined, #{}),
        type => hb_maps:get(<<"type">>, Data, undefined, #{}),
        owner => hb_maps:get(<<"address">>, Owner, undefined, #{}),
        key => hb_maps:get(<<"key">>, Owner, undefined, #{}),
        tags =>
            [
                {
                    hb_maps:get(<<"name">>, Tag, undefined, #{}),
                    hb_maps:get(<<"value">>, Tag, undefined, #{})
                }
            ||
                Tag <- hb_maps:get(<<"tags">>, Item, [], #{})
            ]
    }.

%% @doc The hooks of a running node, by its wallet.
node_hooks(Wallet) ->
    hb_http_server:get_opts(
        #{ <<"http-server">> => hb_util:human_id(ar_wallet:to_address(Wallet)) }
    ).

%% @doc `install' adds both sources and keeps the node's default request
%% hooks, and items uploaded to the bundler by RSA and Ethereum signers are
%% reported with their metadata.
upload_test() ->
    Receiver = start_receiver(),
    {ServerHandle, NodeOpts} =
        hb_mock_server:start_arweave_gateway(
            #{
                price => {200, <<"12345">>},
                tx_anchor => {200, hb_util:encode(rand:bytes(32))}
            }
        ),
    try
        NodeWallet = ar_wallet:new(),
        Node =
            hb_http_server:start_node(
                NodeOpts#{
                    <<"priv-wallet">> => NodeWallet,
                    <<"store">> => hb_test_utils:test_store(),
                    <<"on">> =>
                        #{
                            <<"start">> =>
                                #{
                                    <<"device">> => <<"shepherd-feed@1.0">>,
                                    <<"path">> => <<"install">>
                                }
                        },
                    <<"shepherd-feed-url">> => <<Receiver/binary, "feed">>,
                    <<"shepherd-feed-token">> => <<"test-token">>
                }
            ),
        Hooks = node_hooks(NodeWallet),
        ?assertEqual(
            hb_hook:find(<<"request">>, hb_opts:default_message_with_env()),
            hb_hook:find(<<"request">>, Hooks)
        ),
        lists:foreach(
            fun({Hook, Path}) ->
                ?assert(
                    lists:member(
                        #{
                            <<"device">> => <<"shepherd-feed@1.0">>,
                            <<"path">> => Path
                        },
                        hb_hook:find(Hook, Hooks)
                    )
                )
            end,
            [{<<"response">>, <<"upload">>}, {<<"cache-write">>, <<"copycat">>}]
        ),
        RSAWallet = ar_wallet:new(),
        Items =
            [RSAItem, EthereumItem] =
                [
                    ar_bundles:sign_item(
                        #tx{
                            data = <<"not really a png">>,
                            tags = [{<<"Content-Type">>, <<"image/png">>}]
                        },
                        Wallet
                    )
                ||
                    Wallet <- [RSAWallet, ar_wallet:new(ethereum)]
                ],
        lists:foreach(
            fun(Item) ->
                ?assertMatch(
                    {ok, _},
                    hb_http:post(
                        Node,
                        #{
                            <<"path">> => <<"/~bundler@1.0/tx">>,
                            <<"bundler-subject">> => <<"body">>,
                            <<"body">> =>
                                hb_message:convert(
                                    Item,
                                    <<"structured@1.0">>,
                                    <<"ans104@1.0">>,
                                    #{}
                                )
                        },
                        #{}
                    )
                )
            end,
            Items
        ),
        % An Ethereum signer's address is its native `0x' address, as in
        % GraphQL; its public key is reported alongside it.
        EthereumAddress =
            hb_util:human_id(
                ar_wallet:to_address(
                    EthereumItem#tx.owner,
                    EthereumItem#tx.signature_type
                )
            ),
        ?assertMatch(<<"0x", _/binary>>, EthereumAddress),
        RSAAddress = hb_util:human_id(ar_wallet:to_address(RSAWallet)),
        ?assertEqual(
            {
                <<"Bearer test-token">>,
                [
                    #{
                        id => hb_util:encode(RSAItem#tx.id),
                        size => <<"16">>,
                        type => <<"image/png">>,
                        owner => RSAAddress,
                        key => hb_util:encode(RSAItem#tx.owner),
                        tags => [{<<"Content-Type">>, <<"image/png">>}]
                    },
                    #{
                        id => hb_util:encode(EthereumItem#tx.id),
                        size => <<"16">>,
                        type => <<"image/png">>,
                        owner => EthereumAddress,
                        key => hb_util:encode(EthereumItem#tx.owner),
                        tags => [{<<"Content-Type">>, <<"image/png">>}]
                    }
                ]
            },
            receive_report()
        )
    after
        hb_mock_server:stop(ServerHandle)
    end.

%% @doc Without `shepherd-feed-url', `install' restores the default hooks and
%% adds no sources.
install_without_url_test() ->
    NodeWallet = ar_wallet:new(),
    hb_http_server:start_node(
        #{
            <<"priv-wallet">> => NodeWallet,
            <<"store">> => hb_test_utils:test_store(),
            <<"on">> =>
                #{
                    <<"start">> =>
                        #{
                            <<"device">> => <<"shepherd-feed@1.0">>,
                            <<"path">> => <<"install">>
                        }
                }
        }
    ),
    Defaults = hb_opts:default_message_with_env(),
    Live = node_hooks(NodeWallet),
    lists:foreach(
        fun(Hook) ->
            ?assertEqual(hb_hook:find(Hook, Defaults), hb_hook:find(Hook, Live))
        end,
        [<<"request">>, <<"response">>, <<"cache-write">>]
    ).

%% @doc Through the `copycat' source, an item written at a weave offset is
%% reported and an item written without one is not.
copycat_test() ->
    Receiver = start_receiver(),
    Opts =
        #{
            <<"priv-wallet">> => ar_wallet:new(),
            <<"store">> => hb_test_utils:test_store(),
            <<"on">> =>
                #{
                    <<"cache-write">> =>
                        [
                            #{
                                <<"device">> => <<"shepherd-feed@1.0">>,
                                <<"path">> => <<"copycat">>
                            }
                        ]
                },
            <<"shepherd-feed-url">> => <<Receiver/binary, "feed">>
        },
    [Unplaced, Placed] =
        [
            hb_message:commit(#{ <<"a">> => Value }, Opts, <<"ans104@1.0">>)
        ||
            Value <- [<<"1">>, <<"2">>]
        ],
    {ok, _} = hb_cache:write(Unplaced, Opts),
    {ok, _} =
        hb_cache:write(hb_private:set(Placed, <<"offset">>, 1000, Opts), Opts),
    {_Authorization, Report} = receive_report(),
    ?assertEqual(
        [hb_message:id(Placed, signed, Opts)],
        [maps:get(id, Item) || Item <- Report]
    ).
