# Architecture

remote-access glues three mature projects together instead of rewriting them:

| Role | Upstream | Why |
|---|---|---|
| Host capture/encode/stream | **Apollo** (fork of Sunshine) | Best-in-class low-latency game streaming, virtual display, per-client permissions, one-time PINs |
| Client decode/render/input | **Moonlight Qt** | Hardware decode everywhere, gamepads, HDR, 4:4:4, mature CLI |
| UX model | **RustDesk** | 9-digit ID + password, rendezvous server, "Your Desktop / Control Remote Desktop", in-session toolbar |

RustDesk itself is vendored under `upstream/rustdesk` as the design reference for the ID/password/rendezvous model and for a future port of its file-transfer and clipboard subsystems. No RustDesk code is linked today.

## The problem with stock Moonlight + Apollo

Stock Moonlight needs the user to (1) know the host's IP, (2) add it manually, (3) read a PIN off the client, (4) type it into Apollo's web UI on the host, and (5) (for non-first clients) go back to Apollo's web UI to grant permissions, because Apollo gives non-first clients `view|list` only and they cannot launch anything (`apollo/src/nvhttp.cpp:648-653`).

remote-access collapses that to: enter ID, enter password, press Connect.

## Components

```
                ┌───────────────────────┐
                │   ra-rendezvous       │   untrusted; never sees the password
                │   (ID server, hbbs)   │
                └──────┬────────┬───────┘
      register/poll    │        │  lookup/challenge/pair
                       │        │
   ┌───────────────────┴──┐  ┌──┴──────────────────────┐
   │ HOST                 │  │ CLIENT                  │
   │  ra-host  ──► Apollo │  │  ra / ra-desk           │
   │  (agent)   web API   │  │     │                   │
   │            :47990    │  │     ▼                   │
   │  Apollo GameStream ◄─┼──┼── Moonlight (stream)    │
   │  :47989/:47984/RTSP  │  │   or ra-gamestream      │
   └──────────────────────┘  └─────────────────────────┘
```

* **`crates/ra-proto`** — wire types + the password scheme.
* **`crates/ra-gamestream`** — Rust implementation of the Moonlight client protocol: identity cert, `/serverinfo`, the full 5-step pairing handshake (incl. Apollo's `otpauth`), `/applist`, TLS with client cert + pinned server cert. Tested against a simulated host that implements the server side from `apollo/src/nvhttp.cpp`.
* **`crates/ra-rendezvous`** — HTTP/JSON ID server. Persists registrations; pair requests are in memory.
* **`crates/ra-host`** — host agent. Registers, heartbeats, long-polls for pair requests, verifies the password, delivers the PIN to Apollo (`POST /api/pin`), then applies the configured permission mask (`POST /api/clients/update`).
* **`crates/ra-client`** — `ra` CLI and the library the GUI uses. Resolves an ID, probes every advertised endpoint in parallel, pairs, launches `moonlight stream`.
* **`crates/ra-desk`** — egui desktop window shaped like RustDesk's home screen, with a session panel while streaming.
* **`crates/ra-fakehost`** — simulated Apollo for `scripts/e2e.sh`.

## Pairing flow, step by step

1. Host agent registers: `{id?, token, name, endpoints, password_salt}` → gets a 9-digit ID. `token` is a random secret; the server stores `SHA256(token)`.
2. Client looks up the ID → `{online, endpoints, password_salt}` and probes each endpoint's `/serverinfo` concurrently; the first LAN/VPN/public endpoint that answers wins.
3. Client asks the rendezvous for a challenge (rate limited per host), computes  
   `h1 = SHA256(password ‖ salt)`, `h2 = SHA256(h1 ‖ challenge)`, picks a random 4-digit PIN and seals it with ChaCha20-Poly1305 under `SHA256("ra-pair-v1" ‖ h1 ‖ challenge)`.
4. Client posts `{h2, sealed_pin, device_name}` and *immediately* starts `moonlight pair <host> --pin <PIN>` (or the native pairing). Moonlight's `getservercert` request parks on Apollo until a PIN is entered.
5. Host agent receives the request, checks `h2` in constant time, opens the sealed PIN, and loops `POST /api/pin {pin, name}` until Apollo reports a parked session (Apollo answers `status:false` while none is waiting).
6. Moonlight and Apollo finish the cryptographic handshake themselves. A wrong PIN cannot succeed: phase 3 verifies both a SHA-256 hash chain and an RSA signature.
7. Host agent sees the new client in `/api/clients/list` and sets `perm` to the configured mask (default: all inputs, view/list/launch, clipboard both ways; no server commands).
8. Client streams. Subsequent connections skip 3–7 because Moonlight is paired.

Why not Apollo's `otpauth`? It would let the client pair with no round trip through Apollo's web UI, but the client must know the OTP and passphrase, which would have to travel through the rendezvous. Delivering the PIN *to the host* instead keeps the rendezvous unable to pair anything. `ra-gamestream` still implements `otpauth` for LAN use.

## Trust model

* Rendezvous server: learns IDs, names, addresses, `h2`, and a sealed blob. Cannot derive `h1`, cannot open the PIN, cannot pair itself. A malicious server could replay a pair request; the host would post the same PIN into whatever Moonlight session is parked, but that session can only complete if it also knows the PIN.
* Host agent: needs Apollo web UI credentials (Apollo has a single global web session, so a running agent evicts a browser login when it needs the API).
* Password guessing: the rendezvous limits challenges to 20/min per host; the host agent backs off exponentially on wrong passwords.

## What is deliberately not solved yet

* **NAT traversal.** Moonlight connects directly to the host's GameStream ports. Over the internet this needs a VPN (Tailscale/WireGuard — `ra-host` advertises those interfaces as `vpn` endpoints automatically) or port forwarding. RustDesk's hole-punch/relay model is the roadmap item; see below.
* **In-stream toolbar.** Moonlight renders into an SDL window with hotkeys only. `ra-desk` shows a session panel next to it (disconnect, quit app, switch app, hotkey reference). A real overlay needs a Moonlight fork change.
* **File transfer / chat.** Apollo declares `file_upload`/`file_dwnload` permission bits but has no implementation. Candidate: port RustDesk's `libs/base/src/fs.rs` transfer protocol over a side channel.

## Roadmap

1. `ra-relay`: TCP/UDP relay + UDP hole punching for the GameStream ports, coordinated through the rendezvous (RustDesk `PunchHoleRequest`/`RelayRequest` model).
2. Moonlight fork: "Connect by ID" dialog in `app/gui/main.qml` next to "Add PC manually", calling into `ra-client` (as a C ABI) so the whole flow lives in one window.
3. Apollo fork: `POST /api/pin` that targets a specific `uniqueid` instead of the first parked session.
4. Clipboard sync via Apollo's `/actions/clipboard` from `ra-desk` while a session is active.
5. File transfer.
