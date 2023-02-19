package whisper

import (
	"io"
	"sync"
)

type BufferedMemoryReadWriter struct {
	wbuf *[]byte
	rbuf *[]byte
	wm   *sync.Mutex
	rm   *sync.Mutex
}

var _ io.ReadWriter = &BufferedMemoryReadWriter{}

func BufferedPipe() (*BufferedMemoryReadWriter, *BufferedMemoryReadWriter) {
	buf1 := make([]byte, 0)
	buf2 := make([]byte, 0)
	m1 := &sync.Mutex{}
	m2 := &sync.Mutex{}

	return &BufferedMemoryReadWriter{
			wbuf: &buf1,
			rbuf: &buf2,
			wm:   m1,
			rm:   m2,
		}, &BufferedMemoryReadWriter{
			wbuf: &buf2,
			rbuf: &buf1,
			wm:   m2,
			rm:   m1,
		}
}

func (bmrw *BufferedMemoryReadWriter) Write(p []byte) (int, error) {
	bmrw.wm.Lock()
	defer bmrw.wm.Unlock()

	newBuf := append(*bmrw.wbuf, p...)
	*bmrw.wbuf = newBuf

	return len(p), nil
}

func (bmrw *BufferedMemoryReadWriter) Read(p []byte) (int, error) {
	bmrw.rm.Lock()
	defer bmrw.rm.Unlock()

	maxLen := len(*bmrw.rbuf)
	if len(p) < maxLen {
		maxLen = len(p)
	}

	n := copy(p[:maxLen], (*bmrw.rbuf)[:maxLen])
	newBuf := (*bmrw.rbuf)[n:]
	*bmrw.rbuf = newBuf

	return n, nil
}
