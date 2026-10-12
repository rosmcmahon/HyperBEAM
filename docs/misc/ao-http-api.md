# AO-Core HTTP API Design notes
### Date: 11 Jan, 2025.

The AO-Core protocol is designed to layer a computation system on top of
HTTP Semantics. As such, it offers syntax for HTTP requests that allow users to
easily manipulate and traverse through the computation graph. This document
describes the semantics and syntax of the AO-Core HTTP API.

## Semantics and syntax

- All paths for typical computations start with a base hashpath:
```
GET /hashpath1/...
```
- All keys after the base are interpreted as AO-Core messages individually, in 
a chain. For example, `GET /hashpath1/key1/key2` is equivalent to:
```
GET /hashpath(hashpath1, key1)/key2
```
- Each path segment is interpreted as a key to resolve upon the message for the
resolution of the previous message. The `key` is taken as the full path for
that message during that resolution.
- When AO-Core is not given a base hashpath (the first key is not a 43 character
base64URL encoded string), the request message is assumed to be its own base
message, with the path applied alone as the request (`Message2`).
- Query parameters are treated as equivalent to headers. A query parameter
replaces a header of the same name, unless the request's `signature-input`
names that header. If the request has no `path` key or header, its query
parameters are also added to the request, replacing any keys of the same name,
signed or not.
- When not otherwise specified, a query parameter or header is interpreted as
being present in all messages in the path, in addition to the path key.
- `+` in path segments delimits the `key` and an optional message dictionary. 
For example, `GET /hashpath1/key1+dict1=val1/key2` adds `dict1=val1` to the
message for the resolution of the `key1` key.
- `N.KeyName` in headers or query parameters is interpreted as `KeyName` in the
message dictionary for the resolution of the `N`th key.
- `Key~DevName` in a path segment is interpreted as executing the message with
the `Device` set to `DevName`.
- A dictionary key of form `Key|Type` is interpreted as a type annotation for
`Key`, which can be used to parse the value of the key using HTTP Structured
Fields (RFC 8941).
- Parentheses in key or path segments are interpreted as the result of the 
enclosed path, as if it were an independent invocation. For example, 
`GET /hashpath1/path2+key1=(/hashpath2/key2)` implies that `key1` in the 
message for the resolution of `path2` is the result of the invocation of 
`/hashpath2/key2`.

## Requests and replies

The module documentation of `hb_http_server` and `hb_http` gives these rules
in full.

- A request is decoded with the codec named by its `codec-device` key. Without
that key, it is decoded with the codec of its `content-type`. The node's
`default-codec` is used when the request has neither.
- If a request has commitments, the node keeps only its committed keys. Every
commitment must verify, or the node replies with a 400. The commitments of an
unsigned request are removed.
- The node sets `method` and `host` from the HTTP request. It adds `path`,
`accept` and `accept-bundle` to a request that does not have them.
- A device that authorizes a request by its signer must only read the keys that
the signer committed, after verifying them.
- The HTTP status of a reply is the result's `status`, if that is an integer
from 100 to 599. Otherwise, it is the code of the result's Erlang status. The
node does not add a `status` key to the reply.
- The codec of a reply is the request's `require-codec`, if it has one.
Otherwise, a result with a `content-type` is sent in `httpsig@1.0`. Otherwise,
the codec is the request's `accept-codec`, or its `accept`.
- A result without commitments is sent with its unsigned commitment over its
own keys. A client keeps only the keys of a reply that at least one of its
commitments covers. If the reply has no `status` key, the client adds the HTTP
status as `status`.

## Example workflows

Get the current routes:
```
curl http://host:port/Routes
```

Set a route for a specific path:
```
curl -X POST http://host:port/Routes -H "Priority: 10" \
    -H "Node: http://host:port" -H "Template: /Some/New/Path"
```

Schedule a message on a process:
```
curl -X POST http://host:port/ProcID/Schedule -H "Action: Transfer" \
    -H "Recipient: Address" -H "Quantity: 1337"
```

Run a WASM executable:
```
curl -X POST http://host:port/Init/Compute -H "Device: WASM-64/1.0" \
    -H "2.WASM-Function: fac" -H "2.WASM-Params: [10]" -d @test/test-64.wasm
```

...returning response with a `Hashpath` header. To execute further messages
on the result, use the `Hashpath` as the base hashpath for the next message:
```
curl http://host:port/Hashpath/Compute/Results -H "WASM-Function: fac" \
    -H "WASM-Params: [11]" -d @test/test-64.wasm
```

Assign a message from one process's outbox to the schedule of another:
```
curl -X POST http://host:port/ProcID2/Schedule+Message= \
    (/ProcID1/Compute+Slot=1/Results/Outbox/1)
```

This request is equivalent to:
```
curl http://host:port/Hashpath/Compute/Results?WASM-Function=fac&WASM-Params=[11]
```

Load the WASM computation from an existing hashpath:
```
curl -X POST http://host:port/Init/Compute \
    -H "1.WASM-Image|Resolve: /OldHashpath/Snapshot/WASM" \
    -H "2.WASM-Function: fac" -H "2.WASM-Params: [10]"
```

To fork an existing process to use a new device, we can use the `~` key operator:
```
curl -X POST http://host:port/Schedule~Process/2.0/(/ProcID/Now)+Method=POST
```

To run multiple computations in the same request, with separate headers for
each, we should be able to use `Header#N` modifiers:
```
curl -X POST http://host:port/Init/Compute/Compute -H "Device: WASM-64/1.0" \
    -H "2.WASM-Function: fac" -H "2.WASM-Params: [10]" \
    -H "3.WASM-Function: fac" -H "3.WASM-Params: [11]" \
    -d @test/test-64.wasm
```

This request is equivalent to:
```
curl http://host:port/Init+Device=WASM-64/1.0+Image=ID/Compute+ \
    WASM-Function=fac+WASM-Params=[10]/Compute+WASM-Function=fac&WASM-Params=[11]
```

Gather the node's known commitments (including its own) on a process output:
```
curl http://host:port/ProcID/Compute+Slot=1/Results/Commitments
```

Dry-run a message on top of an AO process state:
```
curl -X POST http://host:port/ProcID/Compute \
    -H "Action: Balance" -H "Recipient: Address"
```
