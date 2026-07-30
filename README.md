# LockPing Agent

> *A safety blanket for forgetful users.*
> **Check. Tap. Locked.**

The on-PC agent for [LockPing](https://rm-worx.be): see from your phone
whether your Windows or Linux PC is locked, and lock it with one tap.

This repo is open source on purpose: you are installing a program that can
lock your PC, so you should be able to read exactly what it does — and what
it deliberately cannot do (no remote unlock, no screen access, no file
access, no telemetry).

## Security model

- **Accountless.** The agent has a stable ID and an X25519 key pair in
  `~/.config/lockping/agent.json` (0600). The private key never leaves
  that file.
- **Pairing.** `run -pair` opens a one-time 5-minute window and prints a
  code (QR in the upcoming mini-UI). Phone and agent prove possession of
  the code via HMAC and exchange public keys; the code itself never
  travels over the wire. Paired devices live in `devices.json`.
- **End-to-end encryption.** Every status/lock message is a NaCl box
  (X25519 + XSalsa20-Poly1305) between agent and paired device. The relay
  only routes opaque blobs. Lock commands carry a nonce + timestamp
  against replay.
- **Deny by default.** Anything that is not a sealed message from a paired
  device is silently ignored — the only plaintext exception is a valid
  pairing request while a window is open.

Full protocol: [docs/protocol.md](docs/protocol.md).

## Quick start (Linux packages)

After installing the rpm/deb:

```
lockping-agent run -pair    # shows a QR code + pairing code (5 min, single use)
```

Scan it with the app at <https://app.lockping.rm-worx.be> ("Pair a PC"),
then stop with Ctrl+C and enable the agent permanently:

```
systemctl --user enable --now lockping-agent
```

The production relay is the built-in default; `-relay` overrides it for
self-hosted or dev setups.

## Usage

```
lockping-agent status                 # print locked/unlocked
lockping-agent lock                   # lock the session
lockping-agent watch                  # print the state now and on every change
lockping-agent run [-relay wss://…]   # connect to the relay and serve paired devices
lockping-agent run -pair              # same, with a QR pairing window (5 minutes)
```

## Platform support

| | Status read | Lock | Shape |
|---|---|---|---|
| Linux | systemd-logind over D-Bus: `LockedHint` + `PropertiesChanged` (event-driven, no polling) | `Session.Lock` | user service |
| Windows | `WTSRegisterSessionNotification` — *in progress* | `LockWorkStation()` | tray app |

macOS is intentionally out of scope.

## Building

```
go build ./...
go test ./...
GOOS=windows go build ./...   # cross-compile check
```

One static binary per OS; no runtime dependencies.

## License

[MIT](LICENSE) — © RM-Worx (Rudy Mertens).
