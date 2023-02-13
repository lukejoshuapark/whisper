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
