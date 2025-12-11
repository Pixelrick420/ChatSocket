# ChatSocket

A multi-room, end-to-end encrypted chat server application written in C. Features password-protected rooms, client-side encryption, secure message broadcasting, and ngrok support for remote connections.

Huge thanks to [STUDevLantern](https://www.youtube.com/@STUDevLantern) on Youtube for making [this](https://www.youtube.com/playlist?list=PLu_a4hjJo1mTiX7v_Uj2TixvjXsNsY7SZ) course on Socket Programming.

## Overview

ChatSocket is a TCP-based chat application that enables multiple users to communicate in separate chat rooms with end-to-end encryption. The server handles room management and message routing, while encryption/decryption occurs entirely on the client side, ensuring that messages remain encrypted during transmission.

## Features

- **Multi-room Support**: Create and join multiple chat rooms
- **End-to-End Encryption**: Messages encrypted client-side using AES-256-CTR
- **Password-Protected Rooms**: Secure rooms with salted and hashed passwords
- **Room-Based Key Derivation**: Each room derives encryption keys from user-provided passwords
- **Concurrent Connections**: Multi-threaded server supporting up to 32 simultaneous clients
- **Command Interface**: Simple command-based interaction for room management
- **Automatic Cleanup**: Inactive rooms automatically cleaned up after 10 minutes
- **Remote Access**: Built-in ngrok support for exposing server to the internet
- **Raw Mode Terminal**: Real-time character input without waiting for Enter key
- **Room Entry Notifications**: Automatic broadcast when users enter rooms
- **Color-Coded Interface**: Visual distinction between messages, errors, and notifications

## Screenshot:
![3 clients connected to one server(top left)](image.png)

## Technical Architecture

### Cryptographic Implementation

#### Encryption
- **Algorithm**: AES-256-CTR (Counter Mode)
- **Key Derivation**: SHA-256 hash of room password
- **IV Generation**: Random 16-byte initialization vector per message
- **Message Format**: `ENC:<base64-encoded-ciphertext>`

#### Password Storage
- **Hashing**: SHA-256 with 10,000 iterations
- **Salt**: 16-byte random salt per room
- **Format**: `<salt_hex>:<hash_hex>`
- **Constant-Time Comparison**: Protection against timing attacks

#### SHA-256 Implementation
The SHA-256 implementation is based on the work from [Lulu's Blog on Lucidar](https://lucidar.me/en/dev-c-cpp/sha-256-in-c-cpp/), with modifications to suit the specific requirements of this application.

### Network Architecture

- **Protocol**: TCP/IPv4
- **Default Port**: 2077 (configurable via `PORT` environment variable)
- **Message Size**: 2048 bytes maximum (MSG_SIZE), configurable by changing memory allocation
- **Connection Model**: One thread per client connection on the server side. On the client side 2 threads are active: 1 for sending and 1 for receiving messages.

### Server Components

#### Room Management
- Maximum 50 concurrent rooms
- Maximum 32 members per room
- Automatic cleanup of inactive rooms (1 hour timeout)
- Password verification with constant-time comparison
- Broadcast notifications for room entry/exit

#### Client Handling
- Thread-per-client model with detached threads
- Mutex-protected shared state
- Command parsing and routing
- Message broadcasting within rooms
- Support for both encrypted and plaintext messages

### Client Components

#### Terminal Interface
- Raw mode terminal input for real-time character processing
- Backspace support for editing input
- Color-coded output (cyan for messages, red for errors, yellow for notifications, green for prompts)
- Clear screen functionality
- Input line preservation during message reception

#### Message Processing
- Separate receive thread for asynchronous message handling
- Automatic encryption detection and decryption
- Base64 encoding/decoding for binary data transmission
- Proper handling of encrypted and plaintext messages
- Username extraction and display

#### Connection Management
- Automatic disconnect detection
- Graceful connection loss handling
- Reconnection support via address specification
- Support for both local and remote server connections

#### Encryption State
- Per-room encryption context
- Key derivation on room entry
- Automatic encryption for messages in protected rooms
- Separate handling for password-protected and public rooms

## Project Structure

```
ChatSocket/
├── Client/
│   ├── client.c           # Client implementation with raw mode terminal
│   ├── client             # Compiled client binary
│   └── run.sh             # Client build and run script
├── Server/
│   ├── server.c           # Server implementation with room notifications
│   ├── server             # Compiled server binary
│   └── run.sh             # Server build and run script with ngrok support
├── Utils/
│   ├── aes.c              # AES encryption implementation
│   ├── aes.h              # AES header
│   ├── sha256.c           # SHA-256 implementation
│   ├── sha256.h           # SHA-256 header
│   ├── socketUtil.c       # Socket utilities and room management
│   └── socketUtil.h       # Socket utilities header
├── Dockerfile             # Container configuration
└── README.md              # This file
```

## Dependencies

### Server
- POSIX threads (pthread)
- Standard C library
- POSIX sockets

### Client
- POSIX threads (pthread)
- OpenSSL (libssl, libcrypto) - for AES operations
- Standard C library
- POSIX sockets
- termios - for raw mode terminal

## Building and Running

### Server

#### Local Server
```bash
cd Server
gcc server.c ../Utils/socketUtil.c ../Utils/sha256.c -o server -lpthread
./server
```

Or use the provided script:
```bash
cd Server
./run.sh
```

The server listens on `0.0.0.0:2077` by default.

#### Remote Server (with ngrok)
```bash
cd Server
./run.sh ngrok [port]
```

This will:
1. Compile and start the server
2. Launch ngrok to expose the server
3. Display the public address for clients to connect to
4. Show the ngrok dashboard URL (http://localhost:4040)

Example:
```bash
./run.sh ngrok 2077
```

Output:
```
================================================
Server Address: 0.tcp.ngrok.io:12345
ngrok Dashboard: http://localhost:4040
================================================
```

### Client

#### Connecting to Local Server
```bash
cd Client
gcc client.c ../Utils/socketUtil.c ../Utils/sha256.c ../Utils/aes.c -o client -lpthread -lssl -lcrypto
./client
```

Or use the provided script:
```bash
cd Client
./run.sh
```

#### Connecting to Remote Server
```bash
cd Client
./run.sh <address:port>
```

Example:
```bash
./run.sh 0.tcp.ngrok.io:12345
```

The client connects to `127.0.0.1:2077` by default. Specify an address to connect to a remote server.

## Usage

### Commands

- `/help` - Display available commands
- `/name <username>` - Set your display name
- `/create <room> -p <password>` - Create a password-protected room
- `/create <room>` - Create a public room (no encryption)
- `/enter <room>` - Enter a room (prompts for password if protected)
- `/leave` - Leave current room
- `/clear` - Clear the terminal screen
- `/exit` - Disconnect from server

### Workflow Example

1. Start the server (with ngrok for remote access):
   ```bash
   cd Server && ./run.sh ngrok 2077
   ```
   Note the public address displayed.

2. Start a client and set your name:
   ```bash
   cd Client && ./run.sh 0.tcp.ngrok.io:12345
   >>> /name Alice
   ```

3. Create an encrypted room:
   ```
   >>> /create secure-room -p mypassword123
   [*] Room 'secure-room' created
   ```

4. Enter the room (same client or another client):
   ```
   >>> /enter secure-room
   [*] Password: mypassword123
   [*] Entered room 'secure-room'
   ```

5. Send encrypted messages:
   ```
   >>> Hello, this message is encrypted!
   << Alice: Hello, this message is encrypted!
   ```

6. Leave the room:
   ```
   >>> /leave
   [*] Left Room
   ```

### Client Interface Features

#### Input Handling
- Type messages in real-time without pressing Enter to submit each character
- Use backspace to edit your message before sending
- Press Enter to send the complete message
- The prompt `>>>` indicates you're ready to type

#### Color Coding
- **Green (`>>>`)**: Input prompt
- **Cyan (`<<`)**: Incoming messages
- **Yellow (`[*]`)**: System notifications (room entry/exit, status messages)
- **Red (`[!]`)**: Errors and warnings


## Security Considerations

### Strengths
- End-to-end encryption ensures server cannot read message content
- AES-256-CTR provides strong encryption
- Salted password hashing with 10,000 iterations
- Constant-time password comparison prevents timing attacks
- Random IV generation for each message
- Encryption keys never transmitted over the network
- Password input hidden in terminal

### Limitations
- Shared room passwords mean all room members have the same decryption key
- No authentication of message origin
- No key exchange mechanism - clients must pre-agree on password
- No protection against replay attacks
- Server can log encrypted messages
- Metadata (usernames, timestamps, room membership) not protected
- ngrok traffic is tunneled through third-party servers


## License

This project is provided as-is for educational purposes.

## Credits

- SHA-256 implementation based on work by [Lucidar](https://lucidar.me/en/dev-c-cpp/sha-256-in-c-cpp/)
- AES implementation using OpenSSL EVP interface
- Socket programming concepts from [STUDevLantern](https://www.youtube.com/@STUDevLantern)
- C standard library and Berkeley sockets
- ngrok for secure tunneling

## Contributing

Contributions are welcome. Please ensure code follows the existing style and includes appropriate error handling. Key areas for contribution:
- Security enhancements
- Performance optimizations
- Additional features
- Bug fixes
- Documentation improvements
- Test coverage

## Contact

For issues, questions, or suggestions, please open an issue on the project repository.
