// Package replaystore provides crash-durable, single-node OIDC replay markers.
package replaystore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const markerVersion = 1

var (
	ErrInvalidConfiguration = errors.New("invalid replay-store configuration")
	ErrInvalidToken         = errors.New("invalid replay token identity")
	ErrStorage              = errors.New("replay-store operation failed")
)

// Store records one immutable marker per issuer/JTI pair. It is safe for
// concurrent use within one process. The backing directory must be on a local
// filesystem whose O_CREATE|O_EXCL and fsync semantics meet the operating
// system contract; this type does not claim distributed-store semantics.
type Store struct {
	mu     sync.RWMutex
	root   *os.Root
	dir    *os.File
	now    func() time.Time
	closed bool
}

type marker struct {
	Version   int       `json:"version"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Open creates or opens an absolute, owner-only marker directory. Existing
// directories with permissions other than 0700 are rejected rather than fixed
// implicitly.
func Open(directory string) (*Store, error) {
	return openWithClock(directory, time.Now)
}

func openWithClock(directory string, now func() time.Time) (*Store, error) {
	if now == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) == string(filepath.Separator) {
		return nil, ErrInvalidConfiguration
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create directory: %v", ErrStorage, err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("%w: inspect directory: %v", ErrStorage, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, fmt.Errorf("%w: directory must be a non-symlink with mode 0700", ErrInvalidConfiguration)
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("%w: open directory root: %v", ErrStorage, err)
	}
	rootInfo, err := root.Stat(".")
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0o700 {
		root.Close()
		return nil, fmt.Errorf("%w: opened root is not an owner-only directory", ErrInvalidConfiguration)
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("%w: open directory for sync: %v", ErrStorage, err)
	}
	return &Store{root: root, dir: dir, now: now}, nil
}

// Consume atomically creates and synchronizes a marker. It returns false with a
// nil error when the issuer/JTI pair was already consumed. Storage uncertainty
// returns an error and leaves any created marker in place, favoring a safe false
// replay over duplicate issuance.
func (s *Store) Consume(issuer, jti string, expiresAt time.Time) (bool, error) {
	if s == nil {
		return false, ErrInvalidConfiguration
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(jti) == "" || !expiresAt.After(s.now().UTC()) {
		return false, ErrInvalidToken
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return false, fmt.Errorf("%w: store is closed", ErrStorage)
	}
	name := markerName(issuer, jti)
	file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%w: create marker: %v", ErrStorage, err)
	}

	payload, err := json.Marshal(marker{Version: markerVersion, ExpiresAt: expiresAt.UTC()})
	if err == nil {
		payload = append(payload, '\n')
		err = writeAll(file, payload)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = s.dir.Sync()
	}
	if err != nil {
		return false, fmt.Errorf("%w: persist marker: %v", ErrStorage, err)
	}
	return true, nil
}

// Close releases the directory handles. Callers must not use the store after
// Close returns.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	dirErr := s.dir.Close()
	rootErr := s.root.Close()
	return errors.Join(dirErr, rootErr)
}

func markerName(issuer, jti string) string {
	hash := sha256.New()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(issuer)))
	hash.Write(length[:])
	hash.Write([]byte(issuer))
	binary.BigEndian.PutUint64(length[:], uint64(len(jti)))
	hash.Write(length[:])
	hash.Write([]byte(jti))
	return hex.EncodeToString(hash.Sum(nil)) + ".used"
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
