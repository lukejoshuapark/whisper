package whisper

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/lukejoshuapark/test"
	"github.com/lukejoshuapark/test/is"
)

func TestSecureReadWriterEndToEndExclusive(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	test.That(t, err, is.Nil)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	bp1, bp2 := BufferedPipe()

	go func() {
		srw1 := NewSecureReadWriterWithPrivateKey(bp1, privateKey)

		_, err = srw1.Write([]byte("Hel"))
		test.That(t, err, is.Nil)

		_, err = srw1.Write([]byte("lo\n"))
		test.That(t, err, is.Nil)

		_, err = srw1.Write([]byte("World\n"))
		test.That(t, err, is.Nil)

		reader := bufio.NewReader(srw1)

		v1, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v1, is.EqualTo("Hello\n"))

		v2, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v2, is.EqualTo("Again\n"))

		wg.Done()
	}()

	go func() {
		srw2 := NewSecureReadWriterWithPublicKey(bp2, publicKey)
		reader := bufio.NewReader(srw2)

		v1, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v1, is.EqualTo("Hello\n"))

		v2, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v2, is.EqualTo("World\n"))

		_, err = srw2.Write([]byte("Hel"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("lo\n"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("Ag"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("ain\n"))
		test.That(t, err, is.Nil)

		wg.Done()
	}()

	wg.Wait()
}

func TestSecureReadWriterEndToEndMutual(t *testing.T) {
	publicKey1, privateKey1, err := ed25519.GenerateKey(rand.Reader)

	test.That(t, err, is.Nil)
	publicKey2, privateKey2, err := ed25519.GenerateKey(rand.Reader)
	test.That(t, err, is.Nil)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	bp1, bp2 := BufferedPipe()

	go func() {
		srw1 := NewSecureReadWriterWithPrivateAndPublicKey(bp1, privateKey1, publicKey2)

		_, err = srw1.Write([]byte("Hel"))
		test.That(t, err, is.Nil)

		_, err = srw1.Write([]byte("lo\n"))
		test.That(t, err, is.Nil)

		_, err = srw1.Write([]byte("World\n"))
		test.That(t, err, is.Nil)

		reader := bufio.NewReader(srw1)

		v1, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v1, is.EqualTo("Hello\n"))

		v2, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v2, is.EqualTo("Again\n"))

		wg.Done()
	}()

	go func() {
		srw2 := NewSecureReadWriterWithPrivateAndPublicKey(bp2, privateKey2, publicKey1)
		reader := bufio.NewReader(srw2)

		v1, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v1, is.EqualTo("Hello\n"))

		v2, err := reader.ReadString('\n')
		test.That(t, err, is.Nil)
		test.That(t, v2, is.EqualTo("World\n"))

		_, err = srw2.Write([]byte("Hel"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("lo\n"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("Ag"))
		test.That(t, err, is.Nil)

		_, err = srw2.Write([]byte("ain\n"))
		test.That(t, err, is.Nil)

		wg.Done()
	}()

	wg.Wait()
}
