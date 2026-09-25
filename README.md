# remote-access

**Apollo/Moonlight streaming with RustDesk ease of use.** Enter a 9-digit ID and a password, press Connect, and you're streaming a remote desktop with Moonlight's latency and Apollo's virtual display — no IPs, no PIN dialogs, no permission clicks on the host.

```
Your Desktop                           Control Remote Desktop
ID   123 456 789   ● Online            Remote ID  [ 987 654 321 ]
Password  ••••••••  change             Password   [ ••••••••     ]
                                       App        [ Desktop      ]
                                                  [   Connect    ]
```

## What's in the box

| Binary | Runs on | Does |
|---|---|---|
| **`ra-desk`** | every PC | **The app.** Host and client in one window, like RustDesk: shows your ID and password, runs the host agent in-process or as a one-click background service, and connects to other IDs. First-run wizard sets up Apollo — no terminal needed. |
| `ra-rendezvous` | a server | ID registry, like RustDesk's `hbbs` |
| `ra-host` | headless hosts | CLI version of the host agent (`init`, `run`, `set-password`, `clients`) |
| `ra` | scripts / terminals | `ra connect 123456789` — resolves, pairs, launches Moonlight |
| `ra-fakehost` | CI | simulated Apollo for tests |

Upstreams are vendored as submodules under `upstream/` and forked under [Tyalor](https://github.com/Tyalor): [Apollo](https://github.com/Tyalor/Apollo), [Sunshine](https://github.com/Tyalor/Sunshine), [moonlight-qt](https://github.com/Tyalor/moonlight-qt), [rustdesk](https://github.com/Tyalor/rustdesk). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces fit and what the trust model is.

## Quick start

Download a build from [Releases](https://github.com/Tyalor/remote-access/releases), or build with Rust stable:

```sh
git clone https://github.com/Tyalor/remote-access   # submodules optional
cd remote-access && cargo build --release
```

**1. Rendezvous server** (any box both sides can reach). One command with automatic HTTPS:

```sh
RA_DOMAIN=rv.example.com docker compose up -d
```

or bare: `ra-rendezvous --listen 0.0.0.0:21114 --state-file /var/lib/ra/hosts.json` behind your own TLS proxy.

**2. Host** (Windows/Linux/macOS with [Apollo](https://github.com/ClassicOldSong/Apollo) installed):

Open `ra-desk`, click **Set up this PC as a host**, enter Apollo's web UI login, pick (or accept the generated) access password, Finish. Your ID and password appear on the left. Tick **Start with system** to stay reachable after a reboot without the window open.

Headless alternative: `ra-host init --rendezvous https://rv.example.com --apollo-username admin && ra-host run`.

**3. Client** (with [Moonlight](https://moonlight-stream.org) installed):

Open `ra-desk`, type the ID and password, Connect. Or from a terminal:

```sh
ra config --rendezvous https://rv.example.com
ra connect 123456789 --app Desktop --remember
```

Over the internet, put both machines on a VPN such as Tailscale (the host advertises VPN interfaces automatically) or forward TCP/UDP 47984–48010 to the host. Built-in relay/hole punching is on the roadmap.

## How it works (short version)

The rendezvous server never sees the password. The client proves it knows the password with a challenge hash and sends a randomly chosen 4-digit Moonlight PIN sealed under a key derived from the password. The host agent verifies the hash, opens the PIN, and types it into Apollo through Apollo's own API while Moonlight's pairing request is waiting, then grants the client full control permissions. From then on the client is a normal paired Moonlight client. Details and the trust model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Development

```sh
cargo test --workspace     # unit tests incl. simulated pairing handshake
./scripts/e2e.sh           # rendezvous + fake Apollo + host agent + client, no GPU needed
```

Useful env: `RA_HOME` (client config dir), `RA_HOST_CONFIG`, `MOONLIGHT_BIN`, `RUST_LOG`.

Pair the built-in Rust GameStream client against a real Apollo to validate the protocol implementation: `ra pair <id> --native` then `ra apps <id>`.

## Licence

GPL-3.0. See `NOTICE` for upstream licences (RustDesk is AGPL-3.0 and is not linked).
