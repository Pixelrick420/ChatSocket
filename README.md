# ChatSocket

ChatSocket is a multi-room chat application written in C for macOS and Linux. It ships with:

- a TLS server
- a raw CLI client
- a modern full-screen terminal UI client

This version is a breaking protocol redesign focused on stronger end-to-end security, better portability across Unix-like systems, and cleaner local bootstrapping.

## Highlights

- Protected rooms are now truly end-to-end encrypted against the server.
- Room access verification and room encryption keys are derived separately.
- Direct messages use a signed ephemeral X25519 handshake and AES-256-GCM.
- The old `ncurses` TUI has been replaced with a custom terminal renderer.
- The `run.sh` scripts can bootstrap build dependencies on macOS and common Linux distros.
- Clients pin the server certificate fingerprint on first successful connection.

## Security Model

### Protected rooms

Protected rooms no longer send the room secret or a directly reusable room key derivative to the server.

- The client generates a random salt.
- The server stores only a salted verifier.
- The room encryption key is derived locally from the room secret with a separate KDF context.
- Room messages are encrypted client-side with AES-256-GCM.

That means the server can decide whether a join proof is valid, but it cannot decrypt the room contents.

### Direct messages

DM sessions use:

- Ed25519 identity keys for long-term identity
- signed ephemeral X25519 key exchange for session setup
- HKDF-SHA256 for session key derivation
- AES-256-GCM for message encryption

This is stronger than the previous static shared-secret DM flow because session keys are no longer just permanent derivatives of the long-lived identity material.

### Transport

The transport layer is still TLS, but clients now pin the server certificate fingerprint on first use.

- First connection to `host:port`: the fingerprint is stored locally.
- Later connections: the fingerprint must match.

This is a trust-on-first-use model, not public CA validation.

## TUI

The new TUI is a custom full-screen terminal interface built directly on ANSI terminal control and raw input handling.

- split conversation and sidebar layout
- room list and DM list on the right
- scrollback with arrow keys
- in-app help with `?`
- dark, modern terminal aesthetic instead of the old `ncurses` look

## Quick Start

### Server

```bash
cd Server
./run.sh
```

### TUI client

```bash
cd Client
./run_tui.sh
```

### CLI client

```bash
cd Client
./run.sh
```

To connect to another host:

```bash
cd Client
./run_tui.sh 192.168.1.100:2077
```

## Dependency Bootstrap

The `run.sh` scripts now check for:

- `gcc`
- `pkg-config`
- OpenSSL development headers/libraries

If anything is missing, the scripts try to install the required packages:

- macOS: Homebrew
- Linux: `apt`, `dnf`, `yum`, `pacman`, or `zypper`

If your system uses another package manager, install the dependencies manually and rerun the script.

## Commands

### Shared client commands

- `/name <name>`: set your local display name and sync it to the server
- `/rooms`: refresh the server room list
- `/create <room>`: create an open room
- `/create <room> -p <secret>`: create a protected room
- `/enter <room>`: enter a room
- `/leave`: leave the current room
- `/dm <token|nick|prefix>`: start a DM
- `/dmleave`: close the active DM session
- `/list`: load locally-known DM history
- `/nick <token|nick|prefix> <name>`: save a local nickname for a DM peer
- `/token`: show your identity token
- `/help`: show help
- `/exit`: disconnect

## Build Notes

The scripts compile with `pkg-config`:

```bash
pkg-config --cflags --libs openssl
```

If you want to compile manually, use the same OpenSSL flags plus `-lpthread`.

## Local State

Client state is stored under `~/.socketchat/` by default.

- `identity.key`: persistent Ed25519 identity seed
- `username`: saved display name
- `dm_*.log`: DM history files
- `dm_nicks.tsv`: token-to-nickname mappings
- `server.crt` / `server.key`: server TLS material
- `known_servers.tsv`: pinned TLS fingerprints by `host:port`

## Limitations

- This pass targets macOS and Linux. Windows support was intentionally deferred.
- The room protection model is still password-based, so weak shared secrets remain guessable offline if the verifier is stolen.
- The TUI is intentionally lightweight and terminal-native; it is not using an external widget toolkit.

## License

MIT
