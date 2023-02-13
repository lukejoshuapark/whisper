package whisper

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"github.com/lukejoshuapark/test"
	"github.com/lukejoshuapark/test/is"
)

func TestSecureReadWriterEndToEnd(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	test.That(t, err, is.Nil)

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		l, err := net.Listen("tcp", ":1")
		test.That(t, err, is.Nil)
		defer l.Close()

		conn1, err := l.Accept()
		test.That(t, err, is.Nil)
		defer conn1.Close()

		srw1 := NewSecureReadWriterWithPrivateKey(conn1, privateKey)

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
		conn2, err := net.Dial("tcp", ":1")
		test.That(t, err, is.Nil)
		defer conn2.Close()

		srw2 := NewSecureReadWriterWithPublicKey(conn2, publicKey)
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
