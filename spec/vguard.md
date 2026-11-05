# VGuard: the read policy of a relay

`vguard` stands between nginx and strfry on a relay of the network. Every
WebSocket of the relay goes through it, every frame goes on as it is, but
a question that could read what is not the asker's is answered by vguard
itself and never reaches strfry.

Why: the relay holds the gift wraps of direct messages (kind 1059),
addressed by `#p`, and the events of groups (kind 9), named by `#h`. Their
contents are sealed; who gets wraps, when, and which groups talk is not.
The key that lets a client past nginx is in every copy of the app, so it
keeps nobody out. strfry 1.1.3 has no read policy of its own (its
`filterValidation` knows `authors`, `#p` and `#e`, not `#h`, and nothing
of NIP-42).

```
client ──wss──▶ nginx :443 ──ws──▶ vguard 127.0.0.1:7778 ──ws──▶ strfry 127.0.0.1:7777
                  │ checks the key (app or peer)
                  │ peer key → X-Veydan-Role: peer
                  ├─ no Upgrade (NIP-11, the page of strfry) ──▶ strfry
                  └─ /.well-known/veydan-access/, /_access ──▶ vguard 127.0.0.1:7779
                     (the access API of a team or a channel, "The access API")
```

## The rules

For REQ and COUNT, each filter; for NEG-OPEN (NIP-77), its one filter. A
question passes only whole: one filter refused refuses it.

| The filter | Passes when |
|---|---|
| `ids`, every one a full event id (64 hex) | always: an id names its event, and nobody guesses one; the push of a message carries one |
| `kinds` names 1059, or no `kinds` | `#p` is not empty and every value in it is the key this connection signed in with (NIP-42) |
| `kinds` names 9, or no `kinds` | `#h` is not empty, no value in it empty |
| any other `kinds` | always (profiles, follow lists, relay lists, presence, the codes of a device link…) |

So a filter without `kinds` must do both, and a filter without `kinds`
and without `#p` and `#h` (`{}`, `{"limit": 100}`, `{"authors": […]}`)
never passes. An empty `kinds` list is read as no `kinds`. A REQ without a
filter does not pass.

What vguard cannot read for certain does not pass at all: `kinds` that are
not whole numbers of 0…65535, a tag list that is not a list of strings,
`ids` that are not full ids, and an object with one key twice anywhere in
the message (parsers settle that differently, and vguard must read what
strfry reads). A message that is no JSON array with its verb first gets a
`NOTICE` and goes nowhere. A binary frame from a client gets a `NOTICE`:
a nostr message is text.

## The answers

| What | Answer | nostr-sdk then |
|---|---|---|
| a REQ or COUNT for wraps of a key, not signed in yet | held until the AUTH (see "Signing in"), then answered; with no AUTH in time `["CLOSED", <id>, "auth-required: …"]` | signs in and asks again |
| the same as NEG-OPEN | held the same way; with no AUTH in time `["NEG-ERR", <id>, "auth-required: …"]` | falls back to a REQ (the app's sync does), which strfry caps at `maxFilterLimit` |
| anything else refused | `CLOSED` / `NEG-ERR` with `restricted: …` or `invalid: …` | gives the subscription up |
| over `max_subs` open subscriptions | `CLOSED` / `NEG-ERR` with `error: too many …` | — |

A refused REQ that would replace an open subscription of the same id
closes the old one at strfry too (`CLOSE`), as strfry would have replaced
it.

## Signing in (NIP-42)

strfry gives a challenge as the connection opens; vguard notes it and
passes it on. The client's `AUTH` is checked by vguard as strfry checks
it: kind 22242, the id and the signature, `created_at` within
`auth_skew_secs` (3 days: the clock of many a phone is off by hours, and a
phone that cannot sign in gets no message at all), a `challenge` tag this
connection was given and has not signed in with yet,
and a `relay` tag that names this relay — `ws` or `wss` and one of
`relay_hosts` (the relay and its aliases); a path or a query (the app key
the app puts there) does not matter. Without that last check a relay
elsewhere could pass our challenge on to its own user and sign in here as
them.

vguard answers the AUTH itself (`OK`), passes it on to strfry as it is,
and drops strfry's own `OK` to it: strfry knows one name of the relay and
compares the whole URL, and the client must know it is signed in before
it asks again. One key per connection, as strfry: a second key is refused.

A challenge signs in once. The same AUTH sent again on the connection,
or another event over the same challenge, is refused (`invalid: not the
challenge of this connection`); the connection stays signed in. So the
wide window of `created_at` opens no replay: an AUTH is good on one
connection (whose challenge is random and its own), for this relay, once.

When a question needs a signed-in key and no challenge has come from
strfry, vguard waits `challenge_wait_ms` (2 s) for one, then gives a
challenge of its own; an AUTH over it stays with vguard.

When a question needs a signed-in key and a challenge is out but the
client has not answered it yet, the question waits for the AUTH, up to
`auth_wait_ms` (5 s). The app asks for its history (NEG-OPEN, then REQ)
as the connection opens, before it has signed in; a refusal sent it to a
plain REQ, which strfry caps at `maxFilterLimit` (500), so a new device
got only the newest 500 wraps. While a question waits, vguard holds
everything else the client sends after it, in order: a later REQ of the
same id, a CLOSE or an EVENT never overtakes it. Only the AUTH goes
ahead. Once the AUTH is answered (taken or refused), the held frames are
answered in the order they came, as if they had come then: signed in,
the question passes; not, it gets `auth-required`. With no AUTH within
`auth_wait_ms`, the same. At most 32 frames or 1 MiB are held; one more
ends the wait at once. A connection waits once: after a wait it ended,
a question is answered at once. `auth_wait_ms = 0`: no wait, the question
is refused at once. A question that waited for strfry's challenge (or got
vguard's own) then waits for the AUTH the same way.

## Peers

nginx names a connection that came with the key of the peers (the router
and the sync of the other relays of the mesh, VPush, `MESH_PEER_KEY`) by
the header `X-Veydan-Role: peer`. nginx sets the header itself: a client's
own never passes (`proxy_set_header` with an empty value drops it).
vguard believes the header only on a connection from this machine. A peer
reads everything; its frames pass untouched.

VPush watches every relay of the network with the key of the peers, by
`#p` of every registered user and `#h` of every group watched: the relay
learns that list (`spec/protocol.md`, "What a push server cannot do").

## Denied keys

The owner of the network can deny a key on every server it runs
(Veydan Cloud, `services/cloud/spec/cloud-api.md` §14), after a report
about it. vcloud lays the denied keys on the relay as a file, one key a
line, 64 lowercase hex, `#` for a comment; vguard reads the file named by
`denied_keys_file` (the kit: `/opt/vguard/data/denied-keys.txt`, written
by the root helper of the agent with the group of the folder), and reads
it again when its mtime changes, at most once a minute. No line in the
config, no file, or an empty file: nobody is denied, and vguard works as
before. A file that does not read never replaces the list read before;
the journal says so.

For a client connection (a peer reads and writes everything, as above):

| What | Answer |
|---|---|
| `AUTH` signed by a denied key | `["OK", <id>, false, "restricted: key denied"]`; the connection is not signed in, so it reads no gift wrap of that key |
| `EVENT` whose `pubkey` is denied (a profile, a follow list, a media authorization of kind 24242, an event of a group…) | `["OK", <id>, false, "blocked: key denied"]`; strfry never gets it |
| `EVENT` vguard cannot read for certain, while somebody is denied | a `NOTICE`, as any message it cannot read |
| `REQ`/`COUNT` whose every filter names `authors` and every author is denied (after the rules above) | answered here as empty: `EOSE` or `["COUNT", <id>, {"count": 0}]`; a REQ that replaced an open one of the same id ends that one at strfry |
| an `EVENT` of a denied key strfry sends back to any other question | dropped on its way to the client |

What it cannot do. A gift wrap (kind 1059) is signed by a key made for
it, so a wrap from a denied key cannot be told from another: a denied key
can still send direct messages, and that is for the apps and the manifest
of the network to refuse. A `COUNT` that names other authors too counts
the denied key's events. Events a denied key stored before the denial
stay in strfry; through vguard nobody gets them.

The counters `denied_auth`, `denied_events`, `denied_answered` and
`denied_dropped` go to the journal with the others.

## Denied groups

The owner can close a whole group on the relays of the network, after a
report on the group (`services/cloud/spec/cloud-api.md` §14.7). vcloud lays
the closed groups beside the denied keys, as a file of their own: one id
of a group a line (the `h` of its events, as the app writes it: 64
lowercase hex for ours; any 1 to 128 printable ASCII characters without a
space are taken), `#` for a comment. vguard reads the file named by
`denied_groups_file` (the kit: `/opt/vguard/data/denied-groups.txt`) and
reads it again as it does the keys: when its mtime changes, at most once
a minute; a file that does not read keeps the list before. No line in the
config, no file, or an empty file: no group is closed. An id is compared
as it is, not folded to lower case.

For a client connection (a peer reads and writes everything):

| What | Answer |
|---|---|
| `REQ`/`COUNT` whose every filter names in `#h` closed groups alone (after the rules above) | answered here as empty: `EOSE` or `["COUNT", <id>, {"count": 0}]`; a REQ that replaced an open one of the same id ends that one at strfry |
| `REQ`/`COUNT` whose `#h` names closed groups among open ones | goes on to strfry **without** the closed ids, and without a filter whose every `#h` was closed; a question that names no closed group goes on byte for byte |
| `NEG-OPEN` whose `#h` names closed groups alone | `["NEG-ERR", <id>, "restricted: group denied"]` |
| `NEG-OPEN` whose `#h` names closed groups among open ones | goes on without the closed ids |
| `EVENT` with an `h` tag of a closed group, whoever signed it (any `h`, not the first alone) | `["OK", <id>, false, "blocked: group denied"]`; strfry never gets it |
| an `EVENT` with an `h` of a closed group strfry sends back to any question (one by `ids`, a sync) | dropped on its way to the client |

Why the ids are taken out rather than the question refused: the app asks
for the events of all its groups in one filter, and one closed group must
not cut a member off from the others. `#h` is a condition every event a
filter matches meets, so a filter whose every `#h` is closed can match the
events of closed groups alone, and nothing is lost by leaving it out; a
`COUNT` without them counts the open groups only.

What it cannot do. The events of a closed group stay in strfry; through
vguard nobody gets them. A group is no key: its members can still sign
in, write in other groups and to each other; their keys are denied apart
("Denied keys"). A relay without vguard, or another relay, still carries
the group: for that the apps read `banned_groups` of the signed manifest
of the network.

The counters `groups_answered` (questions answered as empty or a sync
refused), `groups_filtered` (questions sent on without the closed ids),
`groups_events` and `groups_dropped` go to the journal with the others;
no id is logged.

## Access modes

Since 0.7.0 a server has an access mode, `[access] mode`, one of three.
The app key stays the gate of nginx (it is in every copy of the app, so
in a team or a channel it means nothing for access); who a connection is
comes from the key it signed in with (NIP-42), never from the `pubkey` of
an event: a gift wrap and the events of a keeper are signed by keys of
their own. Membership is per relay: a key in the members file of this
server.

- `open` — anybody with the app key, as before 0.7.0. The default: a
  `vguard.toml` without `[access]` runs as it did, and an EVENT still goes
  on unread while nobody is denied.
- `team` — a company's server. Only its members (and admins) read and
  write; nobody else can use the relay. A member gets in by an invite
  code ("The access API").
- `channel` — a blogger's server. Anybody reads what is public and may
  join a community and comment, slowly; everything else is written by the
  members (the authors) and the admins alone.

A connection is anonymous (not signed in), a guest (signed in with a key
that is neither a member nor an admin) or a member (a member or an admin).
A peer ("Peers") and a denied key ("Denied keys") are as before, in every
mode: the peer passes untouched, the denied key is refused first.

| | `open` | `team` | `channel` |
|---|---|---|---|
| anonymous REQ, COUNT, NEG-OPEN | the rules above | held until the AUTH as a question for wraps is ("Signing in"), then `CLOSED`/`NEG-ERR` `auth-required: this server is for its members` | the rules above: public kinds pass, wraps need `#p` of the signed-in key |
| anonymous EVENT | passes | held the same way, then `["OK", <id>, false, "auth-required: this server is for its members"]` | held the same way, then `OK false auth-required: sign in to write on this server` |
| AUTH of a guest | `OK true` | `OK true`: signed in, not admitted (refusing the AUTH would make nostr-sdk sign in again and again on `auth-required`) | `OK true` |
| REQ, COUNT, NEG-OPEN of a guest | the rules above | `restricted: not a member of this server; ask its admin for an invite` | the rules above (its own wraps by `#p` pass: a community sends it its `channel.issue` so) |
| EVENT of a guest | passes | `OK false restricted: not a member of this server` | see below |
| a member or an admin | the rules above | the rules above | the rules above |

An EVENT of a guest of a channel passes only when

- its kind is one of `guest_kinds` (by default 0, 10002, 10050, 1059,
  1390, 21390: the profile, the relay lists, gift wraps, joining a
  community); else `restricted: on this server only its authors write`
  (`guest_kinds = []` makes a read-only server);
- a wrap (1059, 21059 when listed) names in `p` members or admins alone,
  at least one: a guest writes to the authors, not to other guests; else
  `restricted: a guest writes to the authors of this server only`;
- a profile or a relay list (0, 10002, 10050) is its own: `pubkey` is the
  signed-in key; else `restricted: a guest writes its own profile and
  relay lists only`;
- and the guest has not written `guest_events_per_minute` (30) on this
  connection within the minute (a token bucket, refilled every second);
  else `rate-limited: slow down`. A refused event costs nothing.

nostr-sdk, the client the app is built on, sends an EVENT refused with
`auth-required` again by itself once it has signed in (it signs in on the
challenge that comes with the refusal); with the wait for the AUTH
(`auth_wait_ms`) it never sees the refusal, the event is held until its
AUTH. A `restricted` it gives up.

The counters `access_auth_required`, `access_restricted`, `guest_events`
(events of guests passed), `guest_rate_limited`, `joins` and
`join_refused` go to the journal with the others.

## Members, admins and invites

There are no accounts. The members are `members_file`
(`/opt/vguard/data/members.txt`), one key a line, 64 lowercase hex, `#`
for a comment: the shape of `denied-keys.txt`. vguard reads it at the
start, again when its mtime changes (at most once a minute, as the denied
lists) and at once on SIGHUP. No file: no members. A file that does not
read keeps the list before.

The admins are `admins` of the config, npub or 64 hex: always admitted,
and the keys the admin endpoints of the API answer. An admin is changed
by the config and a restart.

An invite is a code `vi1.<id>.<mac>`: `id` 16 hex of random, `mac` the
first 16 hex of HMAC-SHA256(secret, `"veydan.access.invite.v1\n" + id`),
the secret being `secret_file` (`/opt/vguard/etc/access.key`, at least 32
bytes of random, made by the kit; vguard refuses to start a team or a
channel without it). The invites are `invites_file`
(`/opt/vguard/data/invites.json`):

```json
[{"id": "…16 hex…", "label": "designers", "uses_left": 3, "expires_at": 1794453063, "created_at": 1793848263}]
```

written by a temporary file renamed over it. The file holds no code:
without the secret it opens nothing. A code is good when its mac checks,
its id is listed, `uses_left > 0` and `expires_at > now`; a join takes one
use. A used-up invite stays listed until it expires, so that a second use
is told `invite_used`; an expired one stays listed 30 days more (told
`invite_expired`), then the next write drops it. A revoked one is gone
(`invite_invalid`). The running guard reads the file on every join.

## The access API

HTTP on `listen_http` (`127.0.0.1:7779`), bound only when the mode is not
open. nginx puts it under the relay's host, the paths as they are:
`/.well-known/veydan-access/` and `/_access` (the latter for nginx's own
`auth_request` only). A request marked NIP-98 carries `Authorization:
Nostr <base64 of an event>` of kind 27235, signed by the user's key, with
`u` = `public_url` + the path (and query), `method`, `payload` = sha256 hex
of the body (when there is a body), `created_at` within 60 s of now; an
event opens one request (its id is remembered two minutes). Every answer
but `/_access` is JSON; an error is `{"error": "<word>"}`.

| Request | Answer |
|---|---|
| `GET /.well-known/veydan-access/v1/info` | `200 {"v":1,"mode":"team","invite":true,"join":"/.well-known/veydan-access/v1/join"}`; `invite`: whether a join is possible at all (the mode is not open) |
| `POST …/v1/join` `{"invite":"vi1.…"}`, NIP-98 | the signer appended to `members_file`, admitted at once: `200 {"member":true}` (also for a key admitted already, whose code is not used up). `401 invite_invalid`, `invite_expired`, `invite_used`, `auth_invalid`; `400 bad_request` (the body); `429 rate_limited` past 10 joins a minute from one address (`X-Real-IP` of nginx on this machine, else the socket's); `403 mode_open` |
| `GET …/v1/me`, NIP-98 | `200 {"member":bool,"admin":bool,"mode":"team"}`; `401 auth_invalid` |
| `POST …/v1/members` `{"pubkey":"<hex or npub>"}`, NIP-98 of an admin | `200 {"pubkey":"<hex>","member":true}`; `400 bad_key` |
| `DELETE …/v1/members/<hex or npub>`, NIP-98 of an admin | the file written anew without it: `200 {"pubkey":"<hex>","member":false}` |
| `POST …/v1/invites` `{"uses":1,"days":7,"label":"…"}` (each optional, these the defaults; uses 1–10000, days 1–365, a label of 100 characters on one line), NIP-98 of an admin | `200 {"code":"vi1.…","id":"…","expires_at":N}`; `400 bad_request` |
| `GET …/v1/invites`, NIP-98 of an admin | `200 [{"id","label","uses_left","expires_at","created_at"}]` |
| `DELETE …/v1/invites/<id>`, NIP-98 of an admin | `200 {"revoked":"<id>"}`; `404 not_found` |

An admin endpoint answers `401 auth_invalid` without a good signature,
`403 not_admin` for a key not in `admins`, `403 mode_open` on an open
server. `429 busy` when 100 000 signed requests are remembered at once.
The check of NIP-98 is the one of VPush (`vpush-server/src/auth.rs`); the
two move to a crate of Veydan-Common later.

## Media access

The media host of a team or a channel (Blossom) lets members and admins
alone upload: nginx asks `GET /_access` by `auth_request`, passing the
`Authorization` the app sends with every upload anyway (`Nostr <base64 of a kind 24242 event>`,
BUD-01). vguard checks the signature, the kind and an `expiration` tag
still ahead, and answers `204` when the signer is a member or an admin,
`401` otherwise; no body either way. The authorization may be used again
until it expires (an upload is retried), so nothing is remembered. On an
open server the answer is `204` for any valid authorization (nginx does
not ask there).

## Limits

| `[limits]` | Default | |
|---|---|---|
| `max_frame` | 262144 | the largest frame from a client; strfry's `maxWebsocketPayloadSize`; over it the connection ends (close 1009) |
| `max_subs` | 200 | open REQ (and, apart, NEG-OPEN) per connection; strfry's `maxSubsPerConnection` |
| `max_filters` | 200 | filters in one REQ or COUNT; strfry's `maxReqFilterSize` |
| `max_connections` | 20000 | connections at once; more are closed at once |
| `handshake_secs` | 10 | the WebSocket handshake of nginx |
| `connect_secs` | 5 | the connection to strfry; without it the client's closes (1011) |
| `idle_secs` | 300 | no frame either way; nginx's `proxy_read_timeout`. strfry's ping every 55 s goes on to the client, so a live client never gets there |
| `auth_skew_secs` | 259200 | how far `created_at` of an AUTH may be from now (3 days) |
| `challenge_wait_ms` | 2000 | see "Signing in" |
| `auth_wait_ms` | 5000 | how long a question before the AUTH waits for it; 0: not at all. See "Signing in" |

`[log] metrics_secs` (300 by default) writes the counters to the journal:
connections, peers, questions passed, refused and why, AUTH taken and
refused, own challenges, waits for the AUTH ended by it, by the time
(`auth_wait_expired`) and by too much held (`auth_wait_overflow`), frames
too large, idle ends, strfry not reached, and those of the access modes
("Access modes").
No address and no key is logged. strfry still gets the client's address
as `X-Real-IP`.

## Running it

```
vguard serve --config /opt/vguard/etc/vguard.toml
vguard check-config --config …      every problem of the file at once
vguard probe --config …             REQ kinds 0 limit 0 through vguard to strfry, until EOSE
vguard access --config … invite [--uses N] [--days D] [--label L]
                                    a new invite; its code on stdout, one line
vguard access --config … invite list
                                    one a line: id, uses left, expires at, made at (unix), label; a tab between
vguard access --config … invite revoke <id>
vguard access --config … members list | add <npub|hex> | remove <npub|hex>
                                    one key a line, hex; add and remove print the key
vguard --version
```

SIGHUP reads every list again at once: the denied keys and groups and
the members (`systemctl reload vguard` where the unit has `ExecReload`).

`vguard access` works on the files directly, as the user `vguard` (the
kit calls it so); the running guard reads the members again within a
minute, or at once on SIGHUP, and the invites on every join. It refuses
on an open server (exit 2, the reason on stderr); 1 when a file does not
read or write, or the invite or the member is not there. `check-config`
reads the files of `[access]` that are there and refuses a `secret_file`
shorter than 32 bytes (or missing, when the mode is not open).

The section, with its defaults (a team or a channel needs every file,
`listen_http` and `public_url`; `public_url` is https, or http to this
machine, without a trailing slash):

```toml
[access]
mode = "open"                       # open | team | channel
members_file = "/opt/vguard/data/members.txt"
admins = []                         # npub or 64 hex
invites_file = "/opt/vguard/data/invites.json"
secret_file = "/opt/vguard/etc/access.key"
listen_http = "127.0.0.1:7779"
public_url = "https://relay.example.org"
guest_kinds = [0, 10002, 10050, 1059, 1390, 21390]   # a channel's guests; [] = read-only
guest_events_per_minute = 30
```

On a server of the kit it is part of the relay (`services/server`,
`components/guard.sh`): installed from `bin/vguard` of the kit (made by
`make build-deploy`) or the release named by `VGUARD_VERSION`
(`vguard-linux-<arch>`, signed by the release key as the component
`vguard`; the release of Veydan-Guard since 0.6.0, the release of
Veydan-Push from 0.4.0 to 0.5.1, which carried it beside `vpush`);
started after strfry; nginx is turned to it only once `vguard probe`
answers. Without a vguard the kit puts up no relay: it stops before it
changes anything and names `VGUARD_VERSION`.
