# router_hash / router_ip collapse to 0.0.0.0 when the first Peer Up is a Loc-RIB peer

## Symptom

Every message published by a collector receiving BMP from more than one
router carries the same `router_hash` and `router_ip: "0.0.0.0"`:

```json
{"msg_type":74,"msg_data":{"router_hash":"f1f17934834ae2613699701054ef9684","router_ip":"0.0.0.0","peer_ip":"10.20.1.1", "...": "..."}}
```

`f1f17934834ae2613699701054ef9684` is `md5("0.0.0.0")`.

Consumers cannot tell which BMP router reported an observation. Two routers
monitoring the same BGP peer produce byte-identical `router_hash` +
`peer_hash` pairs, so per-source aggregation, per-source Peer Down handling,
and any "is this route still visible somewhere else" logic are impossible.

## Cause

`pkg/message/peer.go` latches the speaker identity once, on the first Peer Up
message of the session:

```go
p.speakerReadyOnce.Do(func() {
    p.speakerIP = m.LocalIP
    md5Sum := md5.Sum([]byte(p.speakerIP))
    p.speakerHash = hex.EncodeToString(md5Sum[:])
    close(p.speakerReady)
})
```

An RFC 9069 Loc-RIB Instance Peer (`peer_type == 3`) carries no meaningful
local address; the Peer Up reports `0.0.0.0`. Speakers that advertise a
Loc-RIB peer send it before the regular peers, so `speakerIP` latches to
`0.0.0.0` and stays there for the lifetime of the session. Reproduced with
FRR 8.4 `bmp targets`, which sends the Loc-RIB Peer Up first.

## Fix

Do not latch the speaker identity on a Peer Up that cannot supply one: skip
`peer_type == 3` (Loc-RIB Instance Peer) and any Peer Up whose local address
is unspecified, and take the identity from the first Peer Up that has a real
local address. The remote address of the BMP TCP session is an alternative
source that is always available; if it is used, it must be applied
consistently, since it changes what `router_ip` means for existing consumers.

Loc-RIB messages that arrive before a usable identity is known must still be
published, so the fix cannot simply block on a later Peer Up.

## Test

A unit test feeding a Loc-RIB Peer Up followed by a regular Peer Up must
observe `router_ip` equal to the regular peer's local address, not
`0.0.0.0`, on every message produced afterwards, including the Loc-RIB ones.
