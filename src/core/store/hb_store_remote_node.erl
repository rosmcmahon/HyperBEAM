%%% @doc A store module that reads data from another AO node.
%%% Notably, this store only provides the _read_ side of the store interface.
%%% The write side could be added, returning an commitment that the data has
%%% been written to the remote node. In that case, the node would probably want
%%% to upload it to an Arweave bundler to ensure persistence, too.
-module(hb_store_remote_node).
-export([scope/1, type/3, read/3, write/3, link/3, group/3, resolve/3]).
%%% Public utilities.
-export([maybe_cache/2, read_local_cache/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%% @doc Return the scope of this store.
%%
%% For the remote store, the scope is always `remote'.
%%
%% @param StoreOpts A message with the store options (ignored).
%% @returns remote.
scope(_StoreOpts) ->
    remote.

%% @doc Resolve a key path in the remote store.
%%
%% For the remote node store, the key is returned as-is.
%%
%% @param Data A map containing node configuration.
%% @param Key The key to resolve.
%% @returns The resolved key.
resolve(#{ <<"node">> := Node }, #{ <<"resolve">> := Key }, _NodeOpts) ->
    ?event({remote_resolve, {node, Node}, {key, Key}}),
    {ok, Key}.

%% @doc Determine the type of value at a given key.
%%
%% Remote nodes support `simple', `composite', or `{error, not_found}'.
%%
%% @param Opts A map of options (including node configuration).
%% @param Key The key whose value type is determined.
%% @returns `{ok, simple}' or `{ok, composite}' if found, or
%%          `{error, not_found}' otherwise.
type(Opts = #{ <<"node">> := Node }, #{ <<"type">> := Key }, _NodeOpts) ->
    ?event({remote_type, {node, Node}, {key, Key}}),
    case read_request(Opts, Key) of
        {composite, _} -> {ok, composite};
        {ok, _} -> {ok, simple};
        Other -> Other
    end.

%% @doc Read a key from the remote node. A key that is not an ID names the
%% remote node's own state, which its reply cannot be checked against, so it
%% is read only if the store sets `trusted' to `true'.
%%
%% @param Opts A map of options (including node configuration).
%% @param Key The key to read.
%% @returns `{ok, Msg}' on success or `{error, not_found}' if the key is missing.
read_request(Opts, Key) when ?IS_ID(Key) -> remote_read(Opts, Key);
read_request(Opts = #{ <<"trusted">> := true }, Key) -> remote_read(Opts, Key);
read_request(_, _) -> {error, not_found}.

%% @doc Make an HTTP GET request for a key to the remote node and return the
%% committed message.
remote_read(Opts = #{ <<"node">> := Node }, Key) ->
    ?event(store_remote_node, {executing_read, {node, Node}, {key, Key}}),
    Path =
        case ?IS_ID(Key) of
            true -> <<"/~cache@1.0/read=", (hb_util:human_id(Key))/binary>>;
            false -> <<"/~cache@1.0/read">>
        end,
    HTTPRes =
        hb_http:get(
            Node,
            #{ <<"path">> => Path, <<"read">> => Key },
            Opts
        ),
    case HTTPRes of
        {ok, Res} ->
            % returning the whole response to get the test-key
            Msg = without_transport_commitment(Res, Opts),
            ?event(store_remote_node, {read_found, {result, Msg, response, Res}}),
            case not ?IS_ID(Key) orelse has_id(Msg, Key, Opts) of
                true ->
                    maybe_cache(Opts, Msg),
                    {ok, Msg};
                false ->
                    ?event(store_remote_node, {read_other_id, {key, Key}}),
                    {error, not_found}
            end;
        {error, _Err} ->
            ?event(store_remote_node, {read_not_found, {key, Key}}),
            {error, not_found}
    end;
remote_read(_, _) -> {error, not_found}.
read(Opts, #{ <<"read">> := Key }, _NodeOpts) ->
    read_request(Opts, Key).

%% @doc Return whether a message read by an ID has that ID: its uncommitted ID,
%% the ID of one of its commitments, or the combined ID of its commitments, as
%% `hb_cache:write/2' links it under. Its commitments must verify, as a reply
%% names each one by the key that holds it. A binary has the ID of its data.
has_id(Msg, ID, Opts) when is_map(Msg) ->
    lists:member(
        hb_util:human_id(ID),
        [hb_message:id(Msg, none, Opts), hb_message:id(Msg, all, Opts)] ++
            hb_maps:keys(hb_maps:get(<<"commitments">>, Msg, #{}, Opts), Opts)
    ) andalso hb_message:verify(Msg, all, Opts);
has_id(Bin, ID, Opts) ->
    hb_util:human_id(ID) == hb_message:id(Bin, none, Opts).

%% @doc Remove the transport commitments from the response: the replying
%% node's signature over `hashpath', and its unsigned commitment over the keys
%% of its reply, once the keys that it does not cover are removed. The reply's
%% `hashpath' and `status' are removed with them, unless a signed commitment
%% of the message covers them.
without_transport_commitment(Msg, Opts) when is_map(Msg) ->
    {ok, Committed} =
        hb_message:with_only_committed(
            hb_message:without_commitments(
                #{ <<"committed">> => [<<"hashpath">>] },
                Msg,
                Opts
            ),
            Opts
        ),
    hb_message:without_unless_signed(
        [<<"hashpath">>, <<"status">>],
        hb_message:without_commitments(
            #{ <<"keyid">> => <<"constant:ao">> },
            Committed,
            Opts
        ),
        Opts
    );
without_transport_commitment(Res, _Opts) ->
    Res.

%% @doc Cache the data if the cache is enabled. The `local-store' option may
%% either be `false' or a store definition to use as the local cache. The
%% cache links the data to its own IDs alone: its content hash, and the ID of
%% each commitment that verifies. The key the data was requested by is not
%% linked to it, as the data need not be the message with that ID.
maybe_cache(StoreOpts, Data) ->
    ?event({maybe_cache, StoreOpts, Data}),
    try
        % Check if the local store is in our store options.
        case hb_maps:get(<<"local-store">>, StoreOpts, false, StoreOpts) of
            false ->
                skipped;
            Store ->
                case hb_cache:write(Data, #{ <<"store">> => Store }) of
                    {ok, _RootPath} ->
                        ?event(store_remote_node, cached_received),
                        ok;
                    {error, Err} ->
                        ?event(store_remote_node, error_on_local_cache_write),
                        ?event(warning, {error_caching_remote_node_data, Err}),
                        {error, Err}
                end
        end
    catch _:_ ->
        ignored
    end.

%% @doc Read local store cached value. Maintains the `Opts` for the recursive
%% `hb_cache:read` call, but uses the `StoreOpts` as the source of the
%% `local-store` value.
read_local_cache(StoreOpts, ID, Opts) ->
    ?event({read_local_cache, StoreOpts, ID}),
    case hb_maps:get(<<"local-store">>, StoreOpts, false, StoreOpts) of
        false -> {error, not_found};
        Store ->
            CacheOpts = hb_util:deep_merge(Opts, StoreOpts, Opts),
            hb_cache:read(
                ID,
                CacheOpts#{ <<"store">> => Store }
            )
    end.

%% @doc Write a key to the remote node.
%%
%% Uploads each value to the remote cache and then links each requested
%% destination to the uploaded path.
%%
%% @param Opts A map of options (including node configuration).
%% @param Req Map of destination paths to values.
%% @returns `ok' on success or `{error, Reason}' on failure.
write(#{ <<"read-only">> := true }, _Req, _NodeOpts) ->
    {error, not_found};
write(Opts = #{ <<"node">> := Node }, Req, _NodeOpts) when is_map(Req) ->
    ?event({write, {node, Node}, {request, Req}}),
    maps:fold(
        fun(Destination, Value, ok) ->
            case remote_write_value(Opts, Value) of
                {ok, SourcePath} ->
                    remote_link(Opts, hb_path:to_binary(SourcePath), hb_path:to_binary(Destination));
                {error, _} = Error ->
                    Error
            end;
           (_Destination, _Value, Error) ->
            Error
        end,
        ok,
        Req
    ).

%% @doc Link a source to a destination in the remote node.
%%
%% Constructs an HTTP POST link request for the given source and destination,
%% signing the request when a wallet is available.
%%
%% @returns `ok' on success or `{error, Reason}' on failure.
link(#{ <<"read-only">> := true }, _Req, _NodeOpts) ->
    {error, not_found};
link(Opts = #{ <<"node">> := _Node }, Req, _NodeOpts) when is_map(Req) ->
    maps:fold(
        fun(Destination, Source, ok) ->
            remote_link(Opts, hb_path:to_binary(Source), hb_path:to_binary(Destination));
           (_Destination, _Source, Error) ->
            Error
        end,
        ok,
        Req
    ).

%% @doc Create a group in the remote node cache.
group(#{ <<"read-only">> := true }, _Req, _NodeOpts) ->
    {error, not_found};
group(Opts = #{ <<"node">> := _Node }, #{ <<"group">> := Path }, _NodeOpts) ->
    remote_group(Opts, hb_path:to_binary(Path)).

remote_write_value(Opts = #{ <<"node">> := Node }, Value) ->
    Msg = #{
        <<"path">> => <<"/~cache@1.0/write">>,
        <<"type">> => <<"cache-write">>,
        <<"method">> => <<"POST">>,
        <<"body">> => Value
    },
    SignedMsg = hb_message:commit(Msg, Opts),
    case hb_http:post(Node, SignedMsg, Opts) of
        {ok, Response} ->
            case hb_ao:get(<<"status">>, Response, 0, #{}) of
                200 ->
                    case hb_ao:get(<<"path">>, Response, not_found, #{}) of
                        not_found -> {error, missing_path};
                        Path -> {ok, Path}
                    end;
                Status ->
                    {error, {unexpected_status, Status}}
            end;
        {error, Err} ->
            {error, Err}
    end.

remote_link(Opts = #{ <<"node">> := Node }, Source, Destination) ->
    Msg = #{
        <<"path">> => <<"/~cache@1.0/link">>,
        <<"type">> => <<"cache-link">>,
        <<"method">> => <<"POST">>,
        <<"source">> => Source,
        <<"destination">> => Destination
    },
    SignedMsg = hb_message:commit(Msg, Opts),
    case hb_http:post(Node, SignedMsg, Opts) of
        {ok, Response} ->
            case hb_ao:get(<<"status">>, Response, 0, #{}) of
                200 -> ok;
                Status -> {error, {unexpected_status, Status}}
            end;
        {error, Err} ->
            {error, Err}
    end.

remote_group(Opts = #{ <<"node">> := Node }, Path) ->
    Msg = #{
        <<"path">> => <<"/~cache@1.0/group">>,
        <<"type">> => <<"cache-group">>,
        <<"method">> => <<"POST">>,
        <<"group">> => Path
    },
    SignedMsg = hb_message:commit(Msg, Opts),
    case hb_http:post(Node, SignedMsg, Opts) of
        {ok, Response} ->
            case hb_ao:get(<<"status">>, Response, 0, #{}) of
                200 -> ok;
                Status -> {error, {unexpected_status, Status}}
            end;
        {error, Err} ->
            {error, Err}
    end.

%%%--------------------------------------------------------------------
%%% Tests
%%%--------------------------------------------------------------------

%% @doc Test that we can create a store, write a random message to it, then
%% start a remote node with that store, and read the message from it.
read_test() ->
    rand:seed(default),
    LocalStore = #{ 
		<<"store-module">> => hb_store_fs,
		<<"name">> => <<"cache-mainnet">>
	},
    hb_store:reset(LocalStore),
    M = #{ <<"test-key">> => Rand = rand:uniform(1337) },
    ID = hb_message:id(M),
    {ok, ID} =
        hb_cache:write(
			M, 
			#{ <<"store">> => LocalStore }
		),
    ?event({wrote, ID}),
    Node =
        hb_http_server:start_node(
            #{
                <<"store">> => LocalStore
            }
        ),
    RemoteStore = [
		#{ <<"store-module">> => hb_store_remote_node, <<"node">> => Node }
	],
    {ok, RetrievedMsg} = hb_cache:read(ID, #{ <<"store">> => RemoteStore }),
    ?assertMatch(#{ <<"test-key">> := Rand }, hb_cache:ensure_all_loaded(RetrievedMsg)).

read_only_ids_test() ->
    LocalStore = hb_test_utils:test_store(),
    hb_store:reset(LocalStore),
    {ok, ID} =
        hb_cache:write(
			<<"message">>, 
			#{ <<"store">> => LocalStore }
		),
    Node =
        hb_http_server:start_node(
            #{
                <<"store">> => LocalStore
            }
        ),
    RemoteStore = [
		#{ <<"store-module">> => hb_store_remote_node,
           <<"node">> => Node,
           <<"trusted">> => false }
	],
    ?assertEqual({error, not_found}, hb_cache:read(ID, #{ <<"store">> => RemoteStore })).
