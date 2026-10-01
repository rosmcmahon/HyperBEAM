%%% @doc Authorization for typed operations on a node. Only keys committed by
%%% the requested role are returned to the caller.
-module(lib_meta).
-export([is_authorized/4, role/2]).
-include("include/hb.hrl").

%% @doc Verify the role's commitments and require their signed operation type.
%% The admin defaults to the operator, which defaults to the node wallet.
%% HTTP calls authorize the original singleton, before its path is split.
is_authorized(Type, Role, Msg, Opts) when Role == operator; Role == admin ->
    try
        maybe
            Loaded = hb_cache:ensure_loaded(Msg, Opts),
            Identities = role(Role, Opts),
            % Retain signed inputs so their computations cannot be cached.
            [_ | _] ?= hb_message:signers(
                hb_message:with_only_committers(Loaded, Identities, Opts), Opts
            ),
            Original = hb_private:get(<<"http-request">>, Loaded, Loaded, Opts),
            Signed =
                hb_message:with_only_committers(Original, Identities, Opts),
            [_ | _] ?= hb_message:signers(Signed, Opts),
            Authorized = signed_keys(Signed, Opts),
            Type ?= hb_maps:get(<<"type">>, Authorized, not_found, Opts),
            {ok, Authorized}
        else
            _ -> {error, not_authorized}
        end
    catch
        Class:Reason:Stack ->
            ?event(meta_authorization,
                {authorization_error, Class, Reason, {trace, Stack}}
            ),
            {error, not_authorized}
    end.

%% @doc Return the configured identities for a role. Unclaimed roles deny access.
role(admin, Opts) ->
    addresses(hb_opts:get(admin, role(operator, Opts), Opts));
role(operator, Opts) ->
    addresses(
        hb_opts:get(
            operator,
            case hb_opts:get(priv_wallet, unclaimed, Opts) of
                unclaimed -> unclaimed;
                Wallet -> ar_wallet:to_address(Wallet)
            end,
            Opts
        )
    ).

%% @doc Accept a role address or list of addresses in native or human form.
addresses(Address) when ?IS_ID(Address) -> [hb_util:human_id(Address)];
addresses(Addresses) when is_list(Addresses) ->
    [hb_util:human_id(Address) || Address <- Addresses, ?IS_ID(Address)];
addresses(_) -> [].

%% @doc Follow committed children without admitting their uncommitted fields.
signed_keys(Msg, Opts) when is_map(Msg) ->
    true = hb_message:verify(Msg, #{ <<"ids">> => <<"all">> }, Opts),
    {ok, Committed} = hb_message:with_only_committed(Msg, Opts),
    Authorized =
        hb_maps:map(
            fun(<<"commitments">>, Commitments) -> Commitments;
               (_, Value) -> signed_keys(Value, Opts)
            end,
            Committed,
            Opts
        ),
    % Loading and projecting a child must preserve its parent's signature.
    true = hb_message:verify(Authorized, #{ <<"ids">> => <<"all">> }, Opts),
    Authorized;
signed_keys(Link, Opts) when ?IS_LINK(Link) ->
    signed_keys(hb_cache:ensure_loaded(Link, Opts), Opts);
signed_keys(List, Opts) when is_list(List) ->
    [signed_keys(Value, Opts) || Value <- List];
signed_keys(Value, _Opts) -> Value.
