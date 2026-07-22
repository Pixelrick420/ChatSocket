# ChatSocket

ChatSocket is a multi-room chat application written in C for macOS and Linux. It ships with:

- a TLS server
- a raw CLI client
- a modern full-screen terminal UI client

Protocol v4 is a breaking redesign focused on stronger end-to-end security,
bounded parsing, replay resistance, and testable operation.

## Highlights

- Protected rooms are now truly end-to-end encrypted against the server.
- Room messages carry signed sender identity, random session IDs, and monotonic
  replay counters.
- Room access verification and room encryption keys are derived separately.
- Direct messages use session-bound X25519, signed transcripts, AES-256-GCM
  associated data, and monotonic replay counters.
- Rooms expose authenticated member lists and owner-controlled topics.
- The old `ncurses` TUI has been replaced with a custom terminal renderer.
- Normal launch never invokes a package manager or `sudo`.
- Clients pin the server certificate fingerprint on first successful connection.
- Authentication signatures bind the TLS certificate fingerprint, blocking
  first-use signature relays to another server.

## Security Model

### Protected rooms

Protected rooms no longer send the room secret or a directly reusable room key derivative to the server.

- The client generates a random salt and derives keys with versioned scrypt
  parameters (`SCRYPT-32768-8-1`).
- The server stores only a salted verifier.
- The room encryption key is derived locally from the room secret with a separate KDF context.
- Room messages are encrypted client-side with AES-256-GCM.
- Room name, sender name, identity token, session ID, and sequence are bound as
  AES-GCM associated data.
- Every room frame is signed with the sender's Ed25519 identity and checked by
  both the relay and recipients.
- New protected rooms require a secret of at least 12 characters.

That means the server can decide whether a join proof is valid, but it cannot decrypt the room contents.

### Direct messages

DM sessions use:

- Ed25519 identity keys for long-term identity
- signed ephemeral X25519 key exchange for session setup
- HKDF-SHA256 for session key derivation
- AES-256-GCM for message encryption
- random session IDs bound into the signed handshake
- sender, recipient, session, and sequence bound as AES-GCM associated data
- strictly increasing receive counters to reject replay and reordering
- explicit session close and busy rejection, preventing unsolicited handshakes
  from replacing an active DM

This is stronger than the previous static shared-secret DM flow because session keys are no longer just permanent derivatives of the long-lived identity material.

### Transport

The transport layer is still TLS, but clients now pin the server certificate fingerprint on first use.

- First connection to `host:port`: the fingerprint is printed and stored locally.
- Later connections: the fingerprint must match.
- Pin-file access is locked and restricted to the current user.
- TLS handshakes, authentication, initial name setup, frames, and writes use
  bounded deadlines.
- The TLS certificate fingerprint is included in the signed authentication
  transcript.

This is a trust-on-first-use model, not public CA validation.

Each TLS connection is owned by one client event loop. Server-side access to an
OpenSSL connection object is serialized, preventing concurrent `SSL_read` and
`SSL_write` calls on the same object.

## TUI

The new TUI is a custom full-screen terminal interface built directly on ANSI terminal control and raw input handling.

- split conversation and sidebar layout
- room list and DM list on the right
- scrollback with arrow keys
- in-app help with `/help`
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

For an isolated throwaway identity, append `-test` to either client script.

## Dependency Bootstrap

The `run.sh` scripts now check for:

- `gcc`
- `pkg-config`
- OpenSSL development headers/libraries

Normal launch stops with installation instructions when dependencies are
missing. Review and explicitly run:

```bash
./bootstrap.sh --install
```

Supported installers:

- macOS: Homebrew
- Linux: `apt`, `dnf`, `yum`, `pacman`, or `zypper`

If your system uses another package manager, install the dependencies manually and rerun the script.

## Commands

### Shared client commands

- `/name <name>`: set your local display name and sync it to the server
- `/rooms`: refresh the server room list
- `/create <room>`: create an open room
- `/create <room> -p`: create a protected room using a masked secret prompt
- `/create <room> -p <secret>`: create a protected room inline; the masked
  prompt is safer when others can see your terminal
- `/enter <room>`: enter a room
- `/leave`: leave the current room
- `/members`: list current room members with identity fingerprints
- `/topic`: show current room topic
- `/topic <text>`: set topic as room owner
- `/topic -`: clear topic as room owner
- `/dm <contact>`: start a DM by number, nickname, token prefix, or full token
- `/dmleave`: close the active DM session on both peers
- `/list`: show your locally-known DM contacts in recent-first order
- `/search <query>`: search contacts the way you would in a messaging app
- `/nick [@|contact] <name>`: save a local nickname for the active DM or any contact
- `/nick <contact> -`: clear a saved nickname
- `/token`: show your identity token
- `/help`: show help
- `/exit`: disconnect

## Build Notes

The scripts compile with `pkg-config`:

```bash
pkg-config --cflags --libs openssl
```

If you want to compile manually, use the same OpenSSL flags plus `-lpthread`.

Use a vendor-supported, fully patched OpenSSL 3.x release. Homebrew users on
the 3.6 line should use OpenSSL 3.6.3 or newer.

On macOS, ChatSocket uses the system C toolchain plus Homebrew's `pkg-config`
and `openssl@3`. If the Apple command line tools are missing, install them
with:

```bash
xcode-select --install
```

## Build and Test

There is a basic end-to-end CLI smoke test for local regression checking:

```bash
make all
make test
make sanitize
```

It recompiles the server and CLI client, starts a local relay, connects two
test users, exercises open and protected rooms, wrong-secret rejection,
owner-only topics, member listing, protocol-v4 DM handshakes, encrypted DM
traffic, contact search, room-owner transfer, signed room traffic, and session
reopening.

The server also requires a confirmed unique case-insensitive display name,
enforces bounded frame sizes and absolute setup deadlines, limits clients to
100 frames per second, and permits five DM handshakes per second.

## Local State

Client state is stored under `~/.socketchat/` by default.

- `identity.key`: persistent Ed25519 identity seed
- `username`: saved display name
- `dm_*.log`: DM history files
- `dm_nicks.tsv`: token-to-nickname mappings
- `server.crt` / `server.key`: server TLS material
- `known_servers.tsv`: pinned TLS fingerprints by `host:port`

DM history and diagnostic logs remain plaintext inside the user-only config
directory. Disable either before launch when local retention is unwanted:

```bash
SOCKETCHAT_HISTORY=0 SOCKETCHAT_LOG=0 ./Client/run_tui.sh
```

## Limitations

- This pass targets macOS and Linux. Windows support was intentionally deferred.
- Trust on first use cannot detect an attacker present during the first
  connection. Verify the printed fingerprint through another channel when the
  server matters.
- Protected rooms remain password-based. The 12-character minimum helps, but
  predictable secrets can still be guessed offline if the verifier is stolen.
- Replay tracking is memory-only and retains the latest 256 room and DM
  sessions per client process.
- Only one active DM session is supported per client UI.
- The TUI is intentionally lightweight and terminal-native; it is not using an external widget toolkit.

## License

MIT
