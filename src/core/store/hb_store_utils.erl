%%% @doc Helper tools for `hb_store` implementations, common across
%%% implementations
-module(hb_store_utils).
-export([list_request_bounds/1, apply_list_bounds/2]).
-export([list_request_bounds/2, apply_list_bounds/3]).
-export([to_path/1, is_data_path/1, child_prefix/1]).
-export([immediate_children/2]).
-include_lib("eunit/include/eunit.hrl").

%% @doc The bounds of a list request as a message: the child it starts
%% from, or `none'; the most children it returns, `batch', or `all'; and
%% its direction, `asc' or `desc'. A request with none of them bounds
%% nothing: every child, in the store's own order.
list_request_bounds(Req) ->
    #{
        <<"from">> => maps:get(<<"from">>, Req, none),
        <<"limit">> =>
            case maps:get(<<"limit">>, Req, all) of
                all -> all;
                batch -> batch;
                Limit -> hb_util:int(Limit)
            end,
        <<"direction">> => hb_util:atom(maps:get(<<"direction">>, Req, asc))
    }.

%% @doc Bound batches by a store's `list-batch-size', with at least two
%% children for progress from inclusive cursors. Other limits pass through.
list_request_bounds(Req, Store) ->
    case list_request_bounds(Req) of
        #{ <<"limit">> := batch } = Bounds ->
            Bounds#{ <<"limit">> :=
                max(2, hb_util:int(maps:get(<<"list-batch-size">>, Store, 256))) };
        Bounds -> Bounds
    end.

%% @doc Apply a store's batch policy before selecting its children.
apply_list_bounds(Children, Req, Store) ->
    apply_list_bounds(Children, list_request_bounds(Req, Store)).

%% @doc The children a list request answers with, from every child a store
%% holds: all of them, in the store's own order, unless the request bounds
%% the list -- from a child, in a direction, or up to a limit -- when they
%% are the sorted children within its bounds. A batch is every child.
apply_list_bounds(Children, Req) ->
    case list_request_bounds(Req) of
        #{ <<"from">> := none, <<"limit">> := all, <<"direction">> := asc } ->
            Children;
        #{
            <<"from">> := From,
            <<"limit">> := Limit,
            <<"direction">> := Direction
        } ->
            Ordered =
                case Direction of
                    asc -> lists:sort(Children);
                    desc -> lists:reverse(lists:sort(Children))
                end,
            Ahead =
                lists:dropwhile(
                    fun(Child) -> behind(Direction, Child, From) end,
                    Ordered
                ),
            case Limit of
                Count when is_integer(Count) -> lists:sublist(Ahead, Count);
                _ -> Ahead
            end
    end.

%% @doc Whether a child lies before the start of a bounded list.
behind(_Direction, _Child, none) -> false;
behind(asc, Child, From) -> Child < From;
behind(desc, Child, From) -> Child > From.

%%% Paths laid out as keys, as `hb_store_lmdb' lays them out.

%% @doc Path parts joined into a path.
to_path(PathParts) ->
    hb_util:bin(lists:join(<<"/">>, PathParts)).

%% @doc Return whether a path is the `ni:' name of content-addressed data.
is_data_path(<<"ni:", _/binary>>) -> true;
is_data_path(_) -> false.

%% @doc Find the immediate children of a prefix among the rows under it. A
%% child with a row of its own is given as `{Child, Value}', and a child with
%% only rows below it as `Child'.
immediate_children(Prefix, Rows) ->
    PrefixSize = byte_size(Prefix),
    Children =
        lists:foldl(
            fun({Key, Value}, Acc) ->
                case Key of
                    <<Prefix:PrefixSize/binary, Rest/binary>>
                            when Rest =/= <<>> ->
                        case binary:split(Rest, <<"/">>) of
                            [Child] -> Acc#{ Child => {Child, Value} };
                            [Child, _] ->
                                Acc#{ Child => maps:get(Child, Acc, Child) }
                        end;
                    _ ->
                        Acc
                end
            end,
            #{},
            Rows
        ),
    [Child || {_, Child} <- lists:sort(maps:to_list(Children))].

%% @doc The prefix of a path's children: the path and a `/', with none at
%% the root.
child_prefix(<<>>) -> <<>>;
child_prefix(<<"/">>) -> <<>>;
child_prefix(Path) ->
    case binary:last(Path) of
        $/ -> Path;
        _ -> <<Path/binary, "/">>
    end.

%%% Tests

%% @doc Every store lists a path's children whole by default, however
%% many; from a child it lists the path's sorted children from that child,
%% inclusive, in either direction, up to its limit or as a batch.
list_request_bounds_test_() ->
    hb_store:generate_test_suite([{"list bounds", fun list_bounds/1}]).

%% @doc The list bounds test, run against one store.
list_bounds(Store) ->
    lists:foreach(
        fun(Name) ->
            Key = hb_path:to_binary([<<"set">>, Name]),
            ok = hb_store:write(Store, #{ Key => <<>> }, #{})
        end,
        [<<"b">>, <<"d">>, <<"a">>, <<"c">>]
    ),
    List =
        fun(Req) ->
            hb_store:list(Store#{ <<"list-batch-size">> => 2 },
                Req#{ <<"list">> => <<"set">> }, #{})
        end,
    {ok, All} = List(#{}),
    ?assertEqual([<<"a">>, <<"b">>, <<"c">>, <<"d">>], lists:sort(All)),
    ok =
        hb_store:write(
            Store,
            maps:from_list(
                [
                    {hb_path:to_binary([<<"many">>, hb_util:bin(N)]), <<>>}
                ||
                    N <- lists:seq(1, 1500)
                ]
            ),
            #{}
        ),
    {ok, Many} = hb_store:list(Store, <<"many">>, #{}),
    ?assertEqual(1500, length(Many)),
    ?assertMatch({ok, Batch} when length(Batch) =:= 256,
        hb_store:list(Store, #{ <<"list">> => <<"many">>, <<"limit">> => batch }, #{})),
    ?assertEqual(
        {ok, [<<"b">>, <<"c">>]},
        List(#{ <<"from">> => <<"b">>, <<"limit">> => 2 })
    ),
    ?assertEqual(
        {ok, [<<"c">>, <<"d">>]},
        List(#{ <<"from">> => <<"bb">>, <<"limit">> => 5 })
    ),
    ?assertEqual(
        {ok, [<<"c">>, <<"b">>, <<"a">>]},
        List(#{ <<"from">> => <<"c">>, <<"direction">> => <<"desc">> })
    ),
    ?assertEqual(
        {ok, [<<"d">>, <<"c">>]},
        List(#{ <<"direction">> => desc, <<"limit">> => 2 })
    ),
    ?assertEqual(
        {ok, [<<"b">>, <<"c">>]},
        List(#{ <<"from">> => <<"b">>, <<"limit">> => batch })
    ),
    ?assertEqual({ok, []}, List(#{ <<"from">> => <<"e">> })).
