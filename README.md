# ChatSocket

A multi-room, end-to-end encrypted chat application written in C with both CLI and TUI clients. Designed for secure communication with AES-256-CTR encryption for rooms and X25519 key exchange for direct messages.

## Features

- **Multi-room Support**: Create and join separate chat rooms
- **End-to-End Encryption**: AES-256-CTR with password-derived keys for room messages
- **Password-Protected Rooms**: Salted and hashed room passwords using SHA-256
- **Direct Messages**: Encrypted DMs between users using X25519 key exchange
- **Ed25519 Identity**: Persistent Ed25519 key pairs for user authentication
- **TUI Client**: Modern ncurses-based terminal UI with split panels
- **CLI Client**: Original raw-mode terminal client with real-time input
- **TLS Support**: Secure transport layer for all connections
- **Persistence**: Username, identity tokens, and DM nicknames saved locally

## Quick Start

```bash
# Terminal 1: Start server
cd Server && ./run.sh

# Terminal 2: Start TUI client
cd Client && ./run_tui.sh

# Or CLI client
cd Client && ./run.sh
```

Connect to a remote server by passing the address:
```bash
cd Client && ./run_tui.sh 192.168.1.100:2077
```

## Clients

### TUI Client (`client_tui`)

Modern ncurses interface (~1450 lines) with:
- Split panel layout: messages on left (main area), sidebar on right (40 cols)
- Scrollable message history (Up/Down, j/k, PageUp/PageDown, g/G for Home/End)
- Mouse-free navigation with keyboard shortcuts
- Warm/muted color palette (muted cyan for messages, green border for lobby, cyan for rooms, magenta for DMs)
- Scroll position indicator in top bar
- Help overlay (press ? or F1)
- Persistent username saved to `~/.socketchat/username`
- Persistent DM nicknames saved to `~/.socketchat/dm_nicks`
- Auto-connect to server on startup if address saved

### CLI Client (`client`)

Original raw-mode terminal client with:
- Real-time character input without pressing Enter
- Backspace support for editing
- Color-coded output
- Manual connection to any server address

## Commands

| Command | Description |
|---------|-------------|
| `/help` | Display available commands |
| `/name <username>` | Set display name (persisted locally) |
| `/create <room>` | Create a public room |
| `/create <room> -p <pass>` | Create an encrypted room |
| `/enter <room>` | Join a room |
| `/leave` | Leave current room or DM |
| `/rooms` | List available rooms from server |
| `/dm <1\|token>` | Start DM (use index, prefix, or full token) |
| `/dmleave` | Leave current DM session |
| `/list` | Refresh local DM history |
| `/nick <n> <name>` | Rename a DM by index |
| `/token` | Show your Ed25519 identity token |
| `/clear` | Clear current message view |
| `/exit` | Disconnect and quit |

DM syntax supports multiple formats:
- `/dm 1` - use index number
- `/dm abcdef12` - use 8+ character token prefix
- `/dm MyFriend` - use saved nickname
- `/dm <1>` - use indexed reference

## Architecture

### Network

- **Protocol**: TCP/IPv4 with optional TLS
- **Default Port**: 2077
- **Port override**: Set `PORT` environment variable
- **Message Size**: 2048 bytes (configurable in code)

### Cryptography

#### Room Encryption (AES-256-CTR)
- Algorithm: AES-256 in Counter Mode
- Key Derivation: SHA-256 of room password
- IV: 16-byte random per message
- Format: `ENC:<base64-encoded-ciphertext>`

#### Direct Messages (X25519)
- Key Exchange: X25519 Diffie-Hellman
- Identity Keys: Ed25519 key pairs
- Token Format: 64-character hex string
- Per-message encryption with unique nonces

#### Password Storage
- Hashing: SHA-256 with 10,000 iterations
- Salt: 16-byte random per room
- Format: `<salt_hex>:<hash_hex>`
- Constant-time comparison for verification

### Server Components

- Thread-per-client model with detached threads
- Mutex-protected shared state for rooms
- Maximum 50 concurrent rooms
- Maximum 32 members per room
- Broadcast messaging within rooms
- Room entry/exit notifications

### Client State

The TUI maintains several state files in `~/.socketchat/`:
- `username` - Local username display
- `identity` - Ed25519 private key
- `dm_nicks` - Saved DM nicknames (JSON)
- `server` - Last connected server address

## Building

### Server

```bash
cd Server
gcc server.c ../Utils/socketUtil.c ../Utils/sha256.c -o server -lpthread
./server
```

Or use the provided script:
```bash
cd Server && ./run.sh
```

### CLI Client

```bash
cd Client
gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto
./client [address:port]
```

### TUI Client

```bash
cd Client
gcc client_tui.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c ../Utils/identity.c ../Utils/history.c -o client_tui -lpthread -lssl -lcrypto -lncurses
./client_tui [address:port]
```

## Usage Examples

### Basic Room Chat

1. Start server:
   ```bash
   cd Server && ./run.sh
   ```

2. Client A creates room:
   ```
   >>> /name Alice
   >>> /create project-alpha
   [*] Room 'project-alpha' created
   ```

3. Client B joins:
   ```
   >>> /name Bob
   >>> /enter project-alpha
   [*] Entered room 'project-alpha'
   ```

4. Chat:
   ```
   >>> Hello team!
   << Alice: Hello team!
   ```

### Encrypted Room

1. Create password-protected room:
   ```
   >>> /create secrets -p mysecretpassword
   [*] Room 'secrets' created
   ```

2. Others must enter with password:
   ```
   >>> /enter secrets
   [*] Password: ********
   [*] Entered room 'secrets'
   ```

### Direct Messages

1. Get your token:
   ```
   >>> /token
   [*] Token: abc123... (share this with friend)
   ```

2. Start DM using friend's token:
   ```
   >>> /dm abc123def456...
   [*] DM established
   ```

3. Or view DM list and use index:
   ```
   >>> /list
   >>> /dm 1
   ```

4. Rename DM for easy reference:
   ```
   >>> /nick 1 John
   ```

## Security Considerations

### Strengths

- End-to-end encryption - server cannot read message content
- AES-256-CTR - industry-standard encryption
- X25519 - modern elliptic curve key exchange
- Ed25519 - secure identity authentication
- Salted password hashing with high iteration count
- Constant-time password comparison
- Random IVs per message
- Keys never transmitted over network
- TLS option for transport security

### Limitations

- Shared room passwords - all members have same key
- No message authentication (spoofing possible)
- Server logs encrypted metadata
- Username/room membership visible to server
- No forward secrecy

## Troubleshooting

### Connection Issues

- Check server is running: `netstat -tlnp | grep 2077`
- Verify firewall allows port 2077
- Test local connection first: `telnet localhost 2077`

### Build Errors

- Install dependencies:
  ```bash
  # Debian/Ubuntu
  sudo apt install build-essential libssl-dev libncurses-dev
  
  # macOS
  brew install openssl ncurses
  ```

### Runtime Issues

- Ensure `~/.socketchat/` directory exists for TUI
- Check terminal supports 256 colors: `echo $TERM`
- Try alternate TERM: `TERM=screen-256color ./client_tui`

## License

MIT - use as you wish.
