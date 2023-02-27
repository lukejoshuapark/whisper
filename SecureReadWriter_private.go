package whisper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
)

var bytesMagic = []byte("WHSP")
var bytesPublicKeyOnly = []byte{0x00}
var bytesPublicKeyAndSignature = []byte{0x01}

func (srw *SecureReadWriter) performHandshakeIfRequired() error {
	// 1. Check if we've already performed the handshake.
	hasPerformedHandshake := func() bool {
		srw.mx.RLock()
		defer srw.mx.RUnlock()
		return srw.sendAEAD != nil
	}()

	if hasPerformedHandshake {
		return nil
	}

	// 2. Write-lock the mutex.
	srw.mx.Lock()
	defer srw.mx.Unlock()

	// 3. Check again to see if another goroutine bet us here.
	if srw.sendAEAD != nil {
		return nil
	}

	// 4. Set up our record of handshake data sent and received and write the
	// magic bytes.
	var hsSent []byte
	var hsReceived []byte

	if _, err := srw.rw.Write(bytesMagic); err != nil {
		return fmt.Errorf("failed to write handshake magic bytes: %w", err)
	}

	hsSent = append(hsSent, bytesMagic...)

	// 5. Generate our X25519 ECDH private key.
	dhPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// 6. Distribute our public key, and include a signature if we have a
	// ed25519 private key available.  We include an indicator byte to tell the
	// remote end if we are including a signature.
	dhPublicKey := dhPrivateKey.PublicKey()
	dhPublicKeyRaw := dhPublicKey.Bytes()

	if srw.privateKey != nil {
		dhPublicKeyRawSignature := ed25519.Sign(srw.privateKey, dhPublicKeyRaw)
		signaturePayload := append(bytesPublicKeyAndSignature, dhPublicKeyRawSignature...)
		if _, err := srw.rw.Write(signaturePayload); err != nil {
			return fmt.Errorf("failed to write handshake public key and signature: %w", err)
		}

		hsSent = append(hsSent, signaturePayload...)
	} else {
		if _, err := srw.rw.Write(bytesPublicKeyOnly); err != nil {
			return fmt.Errorf("failed to write handshake public key indicator byte: %w", err)
		}

		hsSent = append(hsSent, bytesPublicKeyOnly...)
	}

	if _, err := srw.rw.Write(dhPublicKeyRaw); err != nil {
		return fmt.Errorf("failed to write handshake public key: %w", err)
	}

	hsSent = append(hsSent, dhPublicKeyRaw...)

	// 7. Wait for the remote end of the tunnel to send us their initial
	// handshake payload.
	initialRemoteData := make([]byte, len(bytesMagic)+1)
	if _, err := io.ReadAtLeast(srw.rw, initialRemoteData, len(initialRemoteData)); err != nil {
		return fmt.Errorf("failed to read initial handshake data from remote: %w", err)
	}

	hsReceived = append(hsReceived, initialRemoteData...)

	// 8. Ensure the magic bytes are correct.
	if !bytes.Equal(initialRemoteData[:len(bytesMagic)], bytesMagic) {
		return ErrInvalidHandshake
	}

	// 9. Ensure a valid indicator byte.
	if initialRemoteData[4] != 0x00 && initialRemoteData[4] != 0x01 {
		return ErrInvalidHandshake
	}

	// 10. Ensure we received a signature if we are expecting one.
	signatureProvided := initialRemoteData[4] == 0x01
	if srw.publicKey != nil && !signatureProvided {
		return ErrVerificationOmitted
	}

	// 11. Receive the remaining payload of the handshake.
	remainingPayloadSize := len(dhPublicKeyRaw)
	if signatureProvided {
		remainingPayloadSize += ed25519.SignatureSize
	}

	remainingPayload := make([]byte, remainingPayloadSize)
	if _, err := io.ReadAtLeast(srw.rw, remainingPayload, len(remainingPayload)); err != nil {
		return fmt.Errorf("failed to read remaining handshake data from remote: %w", err)
	}

	hsReceived = append(hsReceived, remainingPayload...)

	// 12. Extract the remote X25519 public key and check the signature, if
	// required.
	var dhPublicKeyRemoteRaw []byte
	if signatureProvided {
		dhPublicKeyRemoteRaw = remainingPayload[ed25519.SignatureSize:]
		dhPublicKeyRemoteRawSignature := remainingPayload[:ed25519.SignatureSize]

		if srw.publicKey != nil && !ed25519.Verify(srw.publicKey, dhPublicKeyRemoteRaw, dhPublicKeyRemoteRawSignature) {
			return ErrVerificationFailed
		}
	} else {
		dhPublicKeyRemoteRaw = remainingPayload[:len(dhPublicKeyRaw)]
	}

	// 13. Build the remote X25519 public key and compute the shared secret.
	dhPublicKeyRemote, err := ecdh.X25519().NewPublicKey(dhPublicKeyRemoteRaw)
	if err != nil {
		return fmt.Errorf("failed to build the remote public key: %w", err)
	}

	sharedSecret, err := dhPrivateKey.ECDH(dhPublicKeyRemote)
	if err != nil {
		return fmt.Errorf("failed to compute the shared secret: %w", err)
	}

	// 14. Combine the sharedSecret and the hashes of the full handshake
	// transcript to get the key material.
	hashSent := sha256.Sum256(hsSent)
	hashReceived := sha256.Sum256(hsReceived)
	hashXOR := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hashXOR[i] = hashSent[i] ^ hashReceived[i]
	}

	finalHasher := sha512.New()
	finalHasher.Write(sharedSecret)
	finalHasher.Write(hashXOR)
	keyMaterial := finalHasher.Sum(nil)
	nonceMaterial := sha256.Sum256(keyMaterial)

	// 15. Determine the send and receive keys, as well as the initial nonces.
	var sendKey, receiveKey, sendNonce, receiveNonce []byte
	if bytes.Compare(hashSent[:], hashReceived[:]) == 1 {
		sendKey = keyMaterial[:32]
		receiveKey = keyMaterial[32:]
		sendNonce = nonceMaterial[:12]
		receiveNonce = nonceMaterial[12:24]
	} else {
		sendKey = keyMaterial[32:]
		receiveKey = keyMaterial[:32]
		sendNonce = nonceMaterial[12:24]
		receiveNonce = nonceMaterial[:12]
	}

	// 16. Construct AEAD's from AES-GCM to use for symmetric encryption.
	sendAES, err := aes.NewCipher(sendKey)
	if err != nil {
		return fmt.Errorf("failed to construct send AES cipher from key material: %w", err)
	}

	receiveAES, err := aes.NewCipher(receiveKey)
	if err != nil {
		return fmt.Errorf("failed to construct receive AES cipher from key material: %w", err)
	}

	sendAEAD, err := cipher.NewGCM(sendAES)
	if err != nil {
		return fmt.Errorf("failed to construct send GCM AEAD from AES cipher: %w", err)
	}

	receiveAEAD, err := cipher.NewGCM(receiveAES)
	if err != nil {
		return fmt.Errorf("failed to construct receive GCM AEAD from AES cipher: %w", err)
	}

	srw.sendAEAD = sendAEAD
	srw.receiveAEAD = receiveAEAD
	srw.sendNonce = sendNonce
	srw.receiveNonce = receiveNonce

	return nil
}

func increaseNonce(nonce []byte) error {
	ind := 11

	for {
		if nonce[ind] != 255 {
			nonce[ind]++
			return nil
		}

		nonce[ind] = 0
		ind--
	}
}

func encrypt(aead cipher.AEAD, nonce, plaintext []byte, w io.Writer) error {
	ciphertextLengthRaw := binary.BigEndian.AppendUint16(nil, uint16(len(plaintext))+16)
	ciphertext := aead.Seal(nil, nonce, plaintext, ciphertextLengthRaw)
	ciphertextAndNonce := append(ciphertextLengthRaw, ciphertext...)

	_, err := w.Write(ciphertextAndNonce)
	return err
}

func decrypt(aead cipher.AEAD, nonce []byte, r io.Reader) ([]byte, error) {
	rawLength := make([]byte, 2)
	_, err := io.ReadAtLeast(r, rawLength, len(rawLength))
	if err != nil {
		return nil, err
	}

	length := int(binary.BigEndian.Uint16(rawLength))
	ciphertext := make([]byte, length)
	_, err = io.ReadAtLeast(r, ciphertext, len(ciphertext))
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, rawLength)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
