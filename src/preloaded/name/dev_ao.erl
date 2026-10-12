%%% @doc The device of the `ao:' URI scheme. An `ao:' URI identifies an
%%% AO-Core message. `hb_uri' reads an `ao:' URI with the `from' key of this
%%% device.
%%%
%%% <pre>
%%%     ao:<ID>         The message with the ID. A bare ID in a path or as a
%%%                     base is read as this URI.
%%%     ao://<path>     An AO-Core path, which is resolved. For example,
%%%                     `ao://with-commitments=<ID>,<ID>' is the message
%%%                     with those commitments.
%%% </pre>
%%%
%%% `to' with `type: uri' writes the URI `ao:<ID>' of a message. `<ID>' is the
%%% ID of the message with all of its commitments.
-module(dev_ao).
-export([from/3, to/3]).
-include("include/hb.hrl").
-include_lib("eunit/include/eunit.hrl").

%% @doc Loads the message that an `ao:' URI identifies. The body is the rest
%% of the URI after `ao:'.
-spec from(
    #{ body := binary(), _ => _ },
    #{ type := binary(), _ => _ },
    #{ _ => _ }
) -> {ok, _} | {error, _}.
from(#{ <<"body">> := Body }, #{ <<"type">> := <<"uri">> }, Opts) ->
    read(Body, Opts).

%% @doc Read the message of an AO-Core path, which we resolve, or of an ID.
read(<<"//", Path/binary>>, Opts) ->
    hb_ao:resolve(Path, Opts);
read(ID, Opts) when ?IS_ID(ID) ->
    hb_cache:read(ID, Opts);
read(_Body, _Opts) ->
    {error, not_found}.

%% @doc Writes the `ao:' URI of a message.
-spec to(
    #{ _ => _ },
    #{ type := binary(), _ => _ },
    #{ _ => _ }
) -> {ok, binary()} | {error, _}.
to(Msg, #{ <<"type">> := <<"uri">> }, Opts) ->
    {ok, <<"ao:", (hb_message:id(Msg, all, Opts))/binary>>}.

%%% Tests

%% @doc Reads three `ao:' URIs: `ao:<ID>', the hashpath `ao://<ID>/a', and
%% `ao://with-commitments=<ID>,<ID>', the message with two commitments.
uri_test() ->
    Opts = #{
        <<"store">> => hb_test_utils:test_store(),
        <<"priv-wallet">> => ar_wallet:new()
    },
    Msg = #{ <<"a">> => <<"1">> },
    {ok, ID} = hb_cache:write(Msg, Opts),
    ?assertEqual({ok, <<"ao:", ID/binary>>}, hb_uri:to(Msg, #{}, Opts)),
    ?assertEqual(
        {ok, <<"1">>},
        hb_ao:resolve(<<"ao:", ID/binary>>, <<"a">>, Opts)
    ),
    ?assertEqual(
        {ok, <<"1">>},
        hb_ao:resolve_many([<<"ao://", ID/binary, "/a">>], Opts)
    ),
    % With `force-message' set, as in an HTTP request, the literal that a URI
    % reads stays a literal.
    ?assertEqual(
        {ok, <<"1">>},
        hb_uri:from(
            <<"ao://", ID/binary, "/a">>,
            Opts#{ <<"force-message">> => true }
        )
    ),
    % A GET of `/ao:<ID>/a' reads the key `a' of the message.
    ?assertEqual(
        {ok, <<"1">>},
        hb_http:get(
            hb_http_server:start_node(Opts),
            <<"/ao:", ID/binary, "/a">>,
            Opts
        )
    ),
    Signed =
        hb_message:commit(
            hb_message:commit(Msg, Opts),
            Opts#{ <<"priv-wallet">> => ar_wallet:new() }
        ),
    {ok, _} = hb_cache:write(Signed, Opts),
    IDs = maps:keys(maps:get(<<"commitments">>, Signed)),
    {ok, Read} =
        hb_ao:resolve_many(
            [
                <<
                    "ao://with-commitments=",
                    (hb_util:bin(lists:join(<<",">>, IDs)))/binary
                >>
            ],
            Opts
        ),
    ?assertEqual(
        hb_message:id(Signed, all, Opts),
        hb_message:id(Read, all, Opts)
    ),
    % The cache writes that path at the combined ID. Reading the combined ID
    % gives the message with both commitments.
    {ok, ReadByID} = hb_cache:read(hb_message:id(Signed, all, Opts), Opts),
    ?assertEqual(
        hb_message:id(Signed, all, Opts),
        hb_message:id(ReadByID, all, Opts)
    ).
