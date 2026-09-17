package replaystore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdwinJdevops/kube-release-envelope/internal/envelope"
)

var _ envelope.TokenConsumer = (*Store)(nil)

func TestMarkerNameUsesUnambiguousLengthPrefixes(t *testing.T) {
	if markerName("ab", "c") == markerName("a", "bc") {
		t.Fatal("distinct issuer/JTI pairs produced the same preimage encoding")
	}
}

func TestConsumeSurvivesStoreRestartWithoutPersistingRawIdentity(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	now := time.Date(2026, 9, 17, 16, 0, 0, 0, time.UTC)
	store, err := openWithClock(directory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := store.Consume("https://token.actions.githubusercontent.com", "sensitive-token-id", now.Add(5*time.Minute))
	if err != nil || !consumed {
		t.Fatalf("Consume() = (%v, %v), want (true, nil)", consumed, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Type().IsRegular() == false {
		t.Fatalf("unexpected marker entries: %#v", entries)
	}
	if strings.Contains(entries[0].Name(), "token") || len(entries[0].Name()) != 64+len(".used") {
		t.Fatalf("marker filename exposes identity or has wrong length: %q", entries[0].Name())
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %o, want 0600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(filepath.Join(directory, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "sensitive-token-id") || strings.Contains(string(payload), "token.actions") {
		t.Fatalf("marker payload exposes raw identity: %s", payload)
	}

	reopened, err := openWithClock(directory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	consumed, err = reopened.Consume("https://token.actions.githubusercontent.com", "sensitive-token-id", now.Add(5*time.Minute))
	if err != nil || consumed {
		t.Fatalf("replayed Consume() = (%v, %v), want (false, nil)", consumed, err)
	}
}

func TestConcurrentConsumeHasOneWinner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	now := time.Date(2026, 9, 17, 16, 0, 0, 0, time.UTC)
	store, err := openWithClock(directory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const workers = 32
	start := make(chan struct{})
	errorsFound := make(chan error, workers)
	var winners atomic.Int32
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			consumed, err := store.Consume("issuer", "same-jti", now.Add(time.Minute))
			if consumed {
				winners.Add(1)
			}
			errorsFound <- err
		}()
	}
	close(start)
	group.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	if winners.Load() != 1 {
		t.Fatalf("successful consumers = %d, want 1", winners.Load())
	}
}

func TestOpenRejectsUnsafeDirectories(t *testing.T) {
	t.Run("relative path", func(t *testing.T) {
		if _, err := Open("relative"); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("Open() error = %v, want ErrInvalidConfiguration", err)
		}
	})

	t.Run("filesystem root", func(t *testing.T) {
		if _, err := Open(string(filepath.Separator)); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("Open() error = %v, want ErrInvalidConfiguration", err)
		}
	})

	t.Run("broad permissions", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "replay")
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(directory); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("Open() error = %v, want ErrInvalidConfiguration", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("Open() error = %v, want ErrInvalidConfiguration", err)
		}
	})
}

func TestConsumeRejectsInvalidOrClosedUse(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "replay")
	now := time.Date(2026, 9, 17, 16, 0, 0, 0, time.UTC)
	store, err := openWithClock(directory, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		issuer string
		jti    string
		expiry time.Time
	}{
		"missing issuer": {jti: "jti", expiry: now.Add(time.Minute)},
		"missing jti":    {issuer: "issuer", expiry: now.Add(time.Minute)},
		"expired":        {issuer: "issuer", jti: "jti", expiry: now},
	} {
		t.Run(name, func(t *testing.T) {
			if consumed, err := store.Consume(test.issuer, test.jti, test.expiry); consumed || !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Consume() = (%v, %v), want (false, ErrInvalidToken)", consumed, err)
			}
		})
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if consumed, err := store.Consume("issuer", "jti", now.Add(time.Minute)); consumed || !errors.Is(err, ErrStorage) {
		t.Fatalf("closed Consume() = (%v, %v), want (false, ErrStorage)", consumed, err)
	}
}
