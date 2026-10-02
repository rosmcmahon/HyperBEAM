%%% @doc A device that looks up an ID from a local store and returns it,
%%% honoring the `accept' key to return the correct format. The cache also
%%% supports writing messages to the store when the node operator has signed
%%% the corresponding cache operation type.
-module(dev_cache).
-device_libraries([lib_meta]).
-export([read/3, write/3, link/3, group/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%% @doc Read data from the cache.
%% Retrieves data corresponding to a key from a local store.
%% The key is extracted from the incoming message under &lt;&lt;"read"&gt;&gt;.
%% The options map may include store configuration.
%% If the "accept" header is set to &lt;&lt;"application/aos-2"&gt;&gt;, the result is 
%% converted to a JSON structure and encoded.
%%
%% @param M1 Ignored parameter.
%% @param M2 The request message containing the key and an optional "accept"
%%            header.
%% @param Opts A map of configuration options.
%% @returns {ok, Data} on success,
%%          {error, not_found} if the key does not exist,
%%          {error, Reason} or {failure, Reason} on failure.
-spec read(
    #{ _ => _ },
    #{ read := binary(), accept => binary(), _ => _ },
    #{ _ => _ }
) -> {ok, _} | {error, _} | {failure, _}.
read(_M1, M2, Opts) ->
    Location = hb_ao:get(<<"read">>, M2, Opts),
    ?event({read, {key_extracted, Location}}),
    ?event(debug_gateway, cache_read),
    case hb_cache:read(Location, Opts) of
        {ok, Res} ->
            ?event({read, {cache_result, ok, Res}}),
            case hb_ao:get(<<"accept">>, M2, Opts) of
                <<"application/aos-2">> ->
                    ?event(dev_cache, 
						{read, 
							{accept_header, <<"application/aos-2">>}
						}
					),
                    {ok, JSONMsg} =
                        hb_ao:resolve(
                            #{ <<"device">> => <<"json-iface@1.0">> },
                            #{
                                <<"path">> => <<"to">>,
                                <<"message">> => Res
                            },
                            Opts
                        ),
                    ?event(dev_cache, {read, {json_message, JSONMsg}}),
                    {ok,
                        #{
                            <<"body">> => hb_json:encode(JSONMsg),
                            <<"content-type">> => <<"application/aos-2">>
                        }
					};
                _ ->
                    {ok, Res}
            end;
        {error, not_found} ->
            % The cache does not have this ID,but it may still be an explicit
            % `data/' path.
            % Store = hb_opts:get(store, [], Opts),
            Store = hb_opts:get(store, no_viable_store, Opts),
            ?event(dev_cache, {read, {location, Location}, {store, Store}}),
            hb_store:read(Store, Location, Opts);
        {error, _} = Error ->
            Error;
        {failure, _} = Failure ->
            Failure
    end.

%% @doc Write a binary or store request on behalf of the node operator.
%% The request must sign `type: cache-write'. Set `write-type: batch' to write
%% each value in a map body separately.
write(_Base, Req, Opts) ->
    maybe
        {ok, Authorized} ?=
            lib_meta:is_authorized(<<"cache-write">>, operator, Req, Opts),
        Body = hb_maps:get(<<"body">>, Authorized, not_found, Opts),
        case hb_maps:get(<<"write-type">>, Authorized, <<"single">>, Opts) of
            <<"single">> -> write_single(Body, Opts);
            <<"batch">> when is_map(Body) ->
                hb_maps:map(
                    fun(_, Value) -> write_single(Value, Opts) end,
                    Body,
                    Opts
                );
            _ ->
                {error,
                    #{ <<"status">> => 400, <<"body">> => <<"Invalid write type.">> }
                }
        end
    end.

%% @doc Link a signed source to a signed destination on behalf of the operator.
link(_Base, Req, Opts) ->
    maybe
        {ok, Authorized} ?=
            lib_meta:is_authorized(<<"cache-link">>, operator, Req, Opts),
        {ok, Destination} ?= hb_maps:find(<<"destination">>, Authorized, Opts),
        {ok, Source} ?= hb_maps:find(<<"source">>, Authorized, Opts),
        wrap_store_result(hb_store:link(#{ Destination => Source }, Opts))
    else
        _ -> {error, not_authorized}
    end.

%% @doc Create a signed cache group on behalf of the operator.
group(_Base, Req, Opts) ->
    maybe
        {ok, Authorized} ?=
            lib_meta:is_authorized(<<"cache-group">>, operator, Req, Opts),
        {ok, Group} ?= hb_maps:find(<<"group">>, Authorized, Opts),
        wrap_store_result(hb_store:group(#{ <<"group">> => Group }, Opts))
    else
        _ -> {error, not_authorized}
    end.

%% @doc Helper function to write a single data item to the cache.
%% Writes store-shaped request maps directly to the store layer, or stores
%% direct binaries in the cache and returns their derived path.
%%
%% @param Body The data to be written.
%% @param Opts A map of configuration options.
%% @returns {ok, #{status := 200, path := Path}} on success,
%%          {error, Reason} on failure.
write_single(Body, Opts) ->
    ?event(dev_cache, {write_single, {body, Body}}),
    case Body of
        not_found ->
            ?event(dev_cache, {write_single, {error, "No body to write"}}),
            {error,
                #{
                    <<"status">> => 400,
                    <<"body">> => <<"No body to write.">>
                }
            };
        Binary when is_binary(Binary) ->
            ?event(dev_cache, {write_single, {processing_binary, Binary}}),
            {ok, Path} = hb_cache:write(Binary, Opts),
            ?event(dev_cache, {write_single, {binary_written, Path}}),
            {ok, #{ <<"status">> => 200, <<"path">> => Path }};
        Req when is_map(Req) ->
            wrap_store_result(hb_store:write(Req, Opts));
        _Other ->
            ?event(dev_cache, {write_single, {error, <<"Invalid write type">>}}),
            {error,
                #{
                    <<"status">> => 400,
                    <<"body">> => <<"Invalid write type.">>
                }
            }
    end.

wrap_store_result(ok) ->
    {ok, #{ <<"status">> => 200 }};
wrap_store_result(OtherResult) ->
    OtherResult.

%%%--------------------------------------------------------------------
%%% Test Helpers
%%%--------------------------------------------------------------------

%% @doc Create a test environment with a local store and node.
%% Ensures that the required application is started, configures a local
%% file-system store, resets the store for a clean state, creates a wallet
%% for signing requests, and starts a node with the store and operator settings.
%%
%% @param StorePrefix A binary specifying the prefix for the local store.
%% @returns {ok, TestOpts, [LocalStore, Wallet, Address, Node]}
setup_test_env() ->
    Timestamp = integer_to_binary(os:system_time(millisecond)),
    StorePrefix = <<"cache-TEST/remote-", Timestamp/binary>>,
    ?event(dev_cache, {setup_test_env, {start, StorePrefix}}),
    application:ensure_all_started(hb),
    ?event(dev_cache, {setup_test_env, {hb_started}}),
    LocalStore = 
		#{ <<"store-module">> => hb_store_fs, <<"name">> => StorePrefix },
    ?event(dev_cache, {setup_test_env, {local_store_configured, LocalStore}}),
    hb_store:reset(LocalStore),
    ?event(dev_cache, {setup_test_env, {store_reset}}),
    Wallet = ar_wallet:new(),
    Address = hb_util:human_id(ar_wallet:to_address(Wallet)),
    ?event(dev_cache, {setup_test_env, {address, Address}}),
    Node = hb_http_server:start_node(#{ 
        <<"cache-control">> => [<<"no-cache">>, <<"no-store">>],
        <<"store">> => LocalStore,
        <<"operator">> => Address,
        <<"store-all-signed">> => false
    }),
    ?event(dev_cache, {setup_test_env, {node_started, Node}}),
    TestOpts = #{
        <<"cache-control">> => [<<"no-cache">>, <<"no-store">>],
        <<"store-all-signed">> => false,
        <<"store">> => [
            #{
                <<"store-module">> => hb_store_remote_node,
                <<"node">> => Node,
                <<"priv-wallet">> => Wallet,
                % The tests read back the `data/' path of a binary they write.
                <<"trusted">> => true
            }
	    ]
    },
    {ok, TestOpts, [LocalStore, Wallet, Address, Node]}.

%%%--------------------------------------------------------------------
%%% Tests
%%%--------------------------------------------------------------------

%% @doc Cache mutations require their own signed type and signed parameters.
typed_cache_mutations_test() ->
    Wallet = ar_wallet:new(),
    Store = hb_test_utils:test_store(),
    Opts = #{ <<"priv-wallet">> => Wallet, <<"store">> => Store,
        <<"http-only-result">> => false },
    Node = hb_http_server:start_node(Opts),
    {ok, Source} = hb_cache:write(<<"cached-value">>, Opts),
    lists:foreach(
        fun({Path, Fields, Unsigned}) ->
            Signed = hb_message:commit(Fields, Opts),
            Req = (maps:merge(Signed, Unsigned))#{ <<"path">> => Path },
            ?assertMatch({error, #{ <<"status">> := 403 }},
                hb_http:post(Node, Req, Opts))
        end,
        [
            {<<"/~cache@1.0/write">>,
                #{ <<"type">> => <<"node-message">>, <<"body">> => <<"wrong-type">> }, #{}},
            {<<"/~cache@1.0/group">>,
                #{ <<"group">> => <<"unsigned-group">> },
                #{ <<"type">> => <<"cache-group">> }},
            {<<"/~cache@1.0/link">>,
                #{ <<"type">> => <<"cache-link">>, <<"source">> => Source },
                #{ <<"destination">> => <<"unsigned-link">> }}
        ]
    ),
    ?assertEqual({error, not_found}, hb_cache:read(<<"unsigned-link">>, Opts)),
    Remote = #{ <<"store-module">> => hb_store_remote_node,
        <<"node">> => Node, <<"priv-wallet">> => Wallet },
    ?assertEqual(ok, hb_store:group(Remote, #{ <<"group">> => <<"authorized-group">> }, Opts)),
    ?assertEqual(ok, hb_store:link(Remote, #{ <<"authorized-link">> => Source }, Opts)),
    ?assertEqual({ok, <<"cached-value">>}, hb_cache:read(<<"authorized-link">>, Opts)).

%% @doc Test that the cache can be written to and read from using the hb_cache
%% API.
cache_write_message_test() ->
    ?event(dev_cache, {cache_api_test, {start}}),
    {ok, Opts, _} = setup_test_env(),
    TestData = #{
        <<"test_key">> => <<"test_value">>
    },
    ?event(dev_cache, {cache_api_test, {opts, Opts}}),
    {ok, Path} = hb_cache:write(TestData, Opts),
    ?event(dev_cache, {cache_api_test, {data_written, Path}}),
    {ok, ReadData} = hb_cache:read(Path, Opts),
    ?event(dev_cache, {cache_api_test, {data_read, ReadData}}),
    ?assert(hb_message:match(TestData, ReadData, only_present, Opts)),
    ?event(dev_cache, {cache_api_test}),
    ok.

%% @doc Ensure that we can write direct binaries to the cache.
cache_write_binary_test() ->
    ?event(dev_cache, {cache_api_test, {start}}),
    {ok, Opts, _} = setup_test_env(),
    TestData = <<"test_binary">>,
    {ok, Path} = hb_cache:write(TestData, Opts),
    {ok, ReadData} = hb_cache:read(Path, Opts),
    ?event(dev_cache, {cache_api_test, {data_read, ReadData}}),
    ?assertEqual(TestData, ReadData),
    ?event(dev_cache, {cache_api_test}),
    ok.
