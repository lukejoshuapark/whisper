![](icon.png)

# whisper

Wraps an `io.ReadWriter` in a secure tunnel using modern elliptic-curve
cryptography.

## Disclaimer

The `whisper` package guarantees confidentiality, integrity and authenticity of
data under non-compromised private keys.  It does not, however, provide any
support for:

- Key lifecycle, including expiration or revocation.
- Hostname verification.
- Trust chains.

All of the above are supported by modern PKC infrastructure (x509, TLS etc.) and
should be preferred for real-world scenarios.

## Configuration

Three `NewSecureReadWriter*` methods are exposed from the `whisper` package:

- `NewSecureReadWriterWithPublicKey`
- `NewSecureReadWriterWithPrivateKey`
- `NewSecureReadWriterWithPrivateAndPublicKey`

If a `SecureReadWriter` has a public key, that public key will be used to verify
the remote end of the tunnel.

If a `SecureReadWriter` has a private key, that private key will be used to
provide verification to the remote end of the tunnel.

This allows for two possible configurations:

- An _exclusive_ tunnel where only one side is verified.  This is analogous to
a typical TLS connection where the server must prove its identity but not the
client.

- A _mutual_ tunnel where both sides are verified.  This is analogous to mutual
TLS where both the client and the server are expected to prove their identities.

## Usage Example

The below example demonstrates how a mutual tunnel might be configured at both
ends.

```go
// These are acquired and/or generated previously.
var remotePublicKey ed25519.PublicKey
var localPrivateKey ed25519.PrivateKey

// The underlying io.ReadWriter can be anything, but in this example, it is a
// net.Conn.
conn, _ := net.Dial("tcp", ":1234")

// We create the *whisper.SecureReadWriter.
srw := whisper.NewSecureReadWriterWithPrivateAndPublicKey(conn, localPrivateKey, remotePublicKey)

// We can now use srw anywhere io.ReadWriter is supported.
lineReader := bufio.NewReader(srw)
line, _ := lineReader.ReadString('\n')
```

## Protocol

The `whisper` protocol uses Ed25519 and X25519 to complete key exchange and
AES-GCM for subsequent encryption of data.

### Key Exchange

Handshaking under the `whisper` protocol only requires a single payload sent in
each direction.  It does not matter which side of the tunnel sends its payload
first and they may be sent asynchronously.

The `whisper` protocol can be utilized in two different modes:

- **Exclusive** - One side of the tunnel holds a Ed25519 Private Key and the
other side holds the corresponding Ed25519 Public Key.  This is similar to how
most typical TLS connections are established e.g. one-sided trust.

- **Mutual** - Both sides of the tunnel hold their own Ed25519 Private Key and
the opposing side's Ed25519 Public Key.

Regardless of the mode of operation, each side of the connection will first
begin by generating a set of ephemeral X25519 keys.  However, the initial
handshake payload will vary.

When using **Exclusive** mode, the side of the tunnel that holds the private key
will send:

```
4  bytes (UTF-8 "WHSP")
1  byte  0x01
64 bytes The signature computed over the generated X25519 Public Key
32 bytes The generated X25519 Public Key
```

Whereas the side that holds the public key will send:

```
4  bytes (UTF-8 "WHSP")
1  byte  0x01
32 bytes The generated X25519 Public Key
```

When using **Mutual** mode, both sides of the tunnel will send the payload that
includes the signature of the generated X25519 Public Key.

Any signatures included are verified before continuing.  Further, a SHA-256 hash
of the outgoing handshake payload and a SHA-256 hash of the incoming handshake
payload are computed and stored.

### Key Generation

Next, the X25519 shared secret is calculated.  The two handshake payload hashes
computed in the previous step are XOR'd together, appended to the shared secret,
then hashed with SHA-512 to get 64 bytes of key material.

The two handshake payload hashes are then compared.  The side of the tunnel that
produced the larger of the two hashes (big-endian) will use the first 32 bytes
of key material to **encrypt** messages, and the remaining 32 bytes to
**decrypt** messages.

The 64 bytes of key material are then hashed with SHA-256.  The first 24 bytes
are the initial nonces.  The same rule applies for which side of the tunnel will
use the first 12 bytes as a nonce when encrypting and which side will use the
subsequent 12 bytes.

### Data Encryption

The `whisper` protocol exchanges data in "messages" that are no more than 65,519
bytes in size.  Messages larger than this amount are broken up and the steps
below are repeated for each segment.  When one side of the tunnel wants to send
a message, it:

- Determines the length of the ciphertext for the provided plaintext.
- Converts this length to an unsigned, big-endian 16-bit integer.
- Encrypts the plaintext using AES-GCM with the correct key and nonce, and
includes the 16-bit integer as additional authenticated data.
- Transmits the 16-bit integer and the ciphertext to the remote party.
- Increments the corresponding nonce.

When one side of the tunnel wants to receive a message, it:

- Waits for at least 16 bits of data to be available and reads them.
- Allocates a buffer of the size specified in those 16 bits.
- Waits for that buffer to fill.
- Decrypts the ciphertext using AES-GCM with the correct key and nonce, and
includes the 16 bits of ciphertext length as additional authenticated data.
- Provides the data back to the caller.
- Increments the corresponding nonce.
