# Changelog

Versions of VGuard are its own and do not follow the app. Tags are
`v<version>`. The numbers continue those of vguard inside Veydan-Push,
where it lived from 0.4.0 to 0.5.1: a kit reads `VGUARD_VERSION` as one
line of numbers.

## 0.7.0 — access modes: open, team, channel

- A server has an access mode, `[access] mode` (`spec/vguard.md`, "Access
  modes"). Who a connection is comes from the key it signed in with
  (NIP-42), never from the `pubkey` of an event; the app key stays the
  gate of nginx and means nothing for access; membership is per relay.
  - `open`: anybody with the app key, as before. The default: a
    `vguard.toml` of 0.6.0, without `[access]`, runs unchanged, and an
    EVENT still goes on unread while nobody is denied.
  - `team`: members and admins alone read and write. Anybody else's
    question or EVENT waits for the AUTH as a question for wraps does,
    then is refused `auth-required: this server is for its members`; a key
    signed in that is not a member gets `OK true` for its AUTH and
    `restricted: not a member of this server…` for everything else.
  - `channel`: anybody reads what is public, as on an open server. An
    EVENT needs a signed-in key; a guest (not a member) writes the kinds
    of `guest_kinds` alone (by default the profile, the relay lists, gift
    wraps and the two kinds of joining a community), a wrap to members
    and admins alone, its own profile and relay lists alone, and
    `guest_events_per_minute` (30) a connection at most
    (`rate-limited: slow down`). Members and admins write anything.
- Members: `members_file`, one key a line as `denied-keys.txt`, read again
  on a change (at most once a minute) and at once on SIGHUP, as are the
  denied lists now (`ExecReload` in `deploy/vguard.service`; the unit may
  write `/opt/vguard/data`). Admins: `admins`, npub or hex.
- Invites: codes `vi1.<id>.<mac>`, an HMAC-SHA256 by `secret_file` (at
  least 32 bytes) over a random id listed in `invites_file` with its uses
  and expiry.
- The access API on `listen_http`, bound only when the mode is not open
  (`spec/vguard.md`, "The access API"): `/.well-known/veydan-access/v1/`
  `info`, `join` (NIP-98 and a code: the signer becomes a member), `me`,
  and for admins `members` and `invites`.
- Media access: `GET /_access` for nginx's `auth_request` of the media
  host: `204` for an upload whose Blossom authorization (kind 24242) a
  member or an admin signed, `401` otherwise.
- `vguard access --config … invite [--uses --days --label] | invite list |
  invite revoke <id> | members list | members add <key> | members remove
  <key>`, on the files; `vguard check-config` reads the files of
  `[access]` and refuses a short key.
- New counters: `access_auth_required`, `access_restricted`,
  `guest_events`, `guest_rate_limited`, `joins`, `join_refused`.
- New crates: `axum` 0.8 (the HTTP API, as VRegistry has it) and
  `base64` (NIP-98), with what they bring (`THIRD-PARTY-LICENSES.md`).

## 0.6.0 — a repository of its own

- VGuard leaves the repository of VPush: `veydanproject/Veydan-Guard`
  holds the crate `vguard`, its specification (`spec/vguard.md`), the
  systemd unit and the example config. The release carries
  `vguard-linux-x86_64` and `vguard-linux-aarch64` with `SHA256SUMS`,
  each signed by the release key as the component `vguard`, as before —
  only the repository is another. A change of the read policy is a
  release of the guard alone; a release of VPush no longer carries it.
- The one crate from outside the folder is `veydan-denied` of
  Veydan-Common (the reader of `denied-keys.txt` and `denied-groups.txt`
  every server of the network shares); the protocol crate of VPush is no
  longer a dependency — the guard never used it.
- Nothing of the policy, the frames or the config changed: a `vguard.toml`
  written for 0.5.1 runs 0.6.0.

## Before 0.6.0

The history of vguard from 0.4.0 to 0.5.1 is in `CHANGELOG.md` of
[Veydan-Push](https://github.com/veydanproject/Veydan-Push): the first
release (0.4.0: the rules, signing in with a lenient clock and a wait for
the AUTH, denied keys, closed groups), the hardening of 0.4.x and 0.5.x,
and the dependency updates of 0.5.1 (tokio 1.54.1).
