package whisper

import (
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
)

// SecureReadWriter is an [io.ReadWriter] that wraps an underlying
// [io.ReadWriter] in a secure tunnel using modern elliptic-curve cryptography.
//
// While this implementation is safe for concurrent use, it is recommended only
// a single goroutine read at a time to avoid lock contention.
type SecureReadWriter struct {
	rw         io.ReadWriter
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	mx         *sync.RWMutex

	aead  cipher.AEAD
	nonce []byte
	buf   []byte
}

var _ io.ReadWriter = &SecureReadWriter{}

// ErrInvalidHandshake is returned when the initial cryptographic handshake
// fails due to some invalid data provided by the remote end of the tunnel.
// This usually indicates the remote end of the tunnel is misconfigured.
var ErrInvalidHandshake = errors.New("the remote end of the tunnel provided invalid handshake data")

// ErrVerificationOmitted is returned when the remote end of the tunnel was
// expected to provide verification, but did not.
var ErrVerificationOmitted = errors.New("verification from the remote end of the tunnel was expected but not provided")

// ErrVerificationFailed is returned when the remote end of the tunnel provided
// verification that was invalid.
var ErrVerificationFailed = errors.New("verification from the remote end of the tunnel was provided but invalid")

// ErrNonceExhaustion is returned when the symmetric key used for the tunnel has
// been used extensively with a given nonce prefix.  The tunnel should be
// re-established.
var ErrNonceExhaustion = errors.New("the set of nonces for this symmetric key has been exhausted")

// Creates a new SecureReadWriter that will verify the remote end of the tunnel
// but not provide any verification itself.
func NewSecureReadWriterWithPublicKey(rw io.ReadWriter, publicKey ed25519.PublicKey) *SecureReadWriter {
	return &SecureReadWriter{
		rw:        rw,
		publicKey: publicKey,
		mx:        &sync.RWMutex{},
	}
}

// Creates a new SecureReadWriter that will provide verification but not verify
// the remote end of the tunnel.
func NewSecureReadWriterWithPrivateKey(rw io.ReadWriter, privateKey ed25519.PrivateKey) *SecureReadWriter {
	return &SecureReadWriter{
		rw:         rw,
		privateKey: privateKey,
		mx:         &sync.RWMutex{},
	}
}

// Creates a new SecureReadWriter that will provide verification and also verify
// the remote end of the tunnel.
func NewSecureReadWriterWithPrivateAndPublicKey(rw io.ReadWriter, privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) *SecureReadWriter {
	return &SecureReadWriter{
		rw:         rw,
		privateKey: privateKey,
		publicKey:  publicKey,
		mx:         &sync.RWMutex{},
	}
}

// Reads data from the underlying [io.ReadWriter].  This method will perform the
// necessary cryptographic handshake with the remote end of the tunnel, if
// required, before reading any data.
//
// It is common for Read to fill p with less bytes than its length.
func (srw *SecureReadWriter) Read(p []byte) (int, error) {
	if err := srw.performHandshakeIfRequired(); err != nil {
		return 0, err
	}

	srw.mx.Lock()
	defer srw.mx.Unlock()

	if len(srw.buf) > 0 {
		max := len(srw.buf)
		if len(p) < max {
			max = len(p)
		}

		copy(p, srw.buf[:max])
		srw.buf = srw.buf[max:]
		return max, nil
	}

	plaintext, err := decrypt(srw.aead, srw.rw)
	if err != nil {
		return 0, fmt.Errorf("failed to decrypt data: %w", err)
	}

	max := len(plaintext)
	if len(p) < max {
		max = len(p)
	}

	copy(p, plaintext[:max])
	srw.buf = plaintext[max:]

	return max, nil
}

// Writes data to the underlying [io.ReadWriter].  This method will perform the
// necessary cryptographic handshake with the remote end of the tunnel, if
// required, before writing any data.
func (srw *SecureReadWriter) Write(p []byte) (int, error) {
	if err := srw.performHandshakeIfRequired(); err != nil {
		return 0, err
	}

	if err := increaseNonce(srw.nonce); err != nil {
		return 0, err
	}

	err := encrypt(srw.aead, srw.nonce, p, srw.rw)
	if err != nil {
		return 0, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return len(p), nil
}
