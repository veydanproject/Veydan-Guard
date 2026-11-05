# VGuard

The read policy of a Veydan relay: a WebSocket proxy between nginx and
strfry. Every frame goes on as it is, but a question (REQ, COUNT, NEG-OPEN)
that could read the gift wraps of another key, or the events of groups it
does not name, is answered here and never reaches strfry. The key a
connection signed in with is NIP-42's.

The relay keeps serving the app, the other relays of the mesh and the push
server as before; what changes is that the metadata of a conversation —
who writes to whom, and when — is read only by the one it is addressed to.

**State: 0.7.0.** In front of every relay of the network since 0.4.0, when
it was built and shipped with VPush; its own repository and release since
0.6.0, with the same numbers. Since 0.7.0 a server has an access mode:
`open` (as before), `team` (members alone, by invite) or `channel`
(anybody reads, the authors write), with an HTTP API for invites and the
members and a check of uploads for the media host.

## Layout

```
crates/vguard         the proxy, as a library, and the binary vguard
deploy/               systemd unit and example config
scripts/              build
spec/vguard.md        the rules, signing in, denied keys and groups, access modes, the access API, running it
```

## Working on it

```
make test            unit tests and tests against a relay of the test's own
make check           clippy, warnings are errors
make run             the guard, here, in front of a strfry on 127.0.0.1:7777
```

The Rust version is the one `rust-toolchain.toml` names. The one crate
taken from outside this folder is `veydan-denied` of
[Veydan-Common](https://github.com/veydanproject/Veydan-Common), the reader
of the lists of denied keys and groups every server of the network shares.

## On a server

`make release` builds one static binary, `dist/vguard`, with its checksum
and release name. The release on GitHub carries `vguard-linux-x86_64` and
`vguard-linux-aarch64`, `SHA256SUMS`, and the signature of each binary by
the release key of the project as the component `vguard`.

The server kit of Veydan ([Veydan-Server](https://github.com/veydanproject/Veydan-Server))
installs it as part of a relay: from `bin/vguard` of the kit or from the
release named by `VGUARD_VERSION`, started after strfry, with nginx turned
to it once `vguard probe` answers. By hand: `deploy/vguard.service` and
`deploy/vguard.example.toml` under `/opt/vguard`, and nginx handing the
WebSocket of the relay to `127.0.0.1:7778` (`spec/vguard.md`, "Running it").

## Licence

VGuard is under the PolyForm Perimeter License 1.0.1, the licence of every
part of Veydan: [LICENSE](LICENSE) is the text that counts, and
[LICENSE-SUMMARY.md](LICENSE-SUMMARY.md) says it in short. In plain words:
you may run the guard, for yourself or for anyone, and read, build, change
and share this source, as long as you do not use it to offer a product that
competes with it. The crates it is built from are listed with their
licences in [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md).
