package identityattempt

import (
	"context"
	"path/filepath"
	"strings"
	"time"
)

const acquisitionLimit = 2 * time.Second
const acquisitionPoll = 25 * time.Millisecond
const leaseLimit = 60 * time.Second
const callLimit = 20 * time.Second
const readyManifest = "{\"schemaVersion\":1,\"storeVersion\":1}\n"

// Location names the fixed private namespace. It holds no native resource.
type Location struct {
	anchor   string
	managed  [3]string
	observer phaseObserver
}

// DefaultLocation selects the platform default without creating persistent state.
func DefaultLocation() (Location, error) {
	anchor, err := defaultConfigRoot()
	if err != nil {
		return Location{}, ErrLocation
	}
	v := Location{anchor: anchor, managed: managedDirectoryNames()}
	if v.validate() != nil {
		return Location{}, ErrLocation
	}
	return v, nil
}

func (v Location) validate() error {
	if !filepath.IsAbs(v.anchor) || filepath.Clean(v.anchor) != v.anchor || strings.IndexByte(v.anchor, 0) >= 0 {
		return ErrLocation
	}
	for _, component := range v.managed {
		if !validLeaf(component) {
			return ErrLocation
		}
	}
	return nil
}

func (v Location) path() string {
	return filepath.Join(v.anchor, v.managed[0], v.managed[1], v.managed[2])
}

func validLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00:") && filepath.Base(name) == name
}

func boundedContext(ctx context.Context) error {
	if ctx == nil {
		return ErrTimeout
	}
	if _, ok := ctx.Deadline(); !ok {
		return ErrTimeout
	}
	return phase(ctx)
}

func remainingDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline, _ := ctx.Deadline()
	return minTime(deadline, time.Now().Add(limit))
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func phase(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrTimeout
	}
	if deadline, present := ctx.Deadline(); present && !time.Now().Before(deadline) {
		return ErrTimeout
	}
	return nil
}

// phaseObserver is an internal commit test boundary. It grants no transport action.
// Production constructors leave it nil. Native actor observers retain real OS calls.
type phaseObserver interface{ Observe(string) error }

func observe(ctx context.Context, observer phaseObserver, stage string) error {
	if err := phase(ctx); err != nil {
		return err
	}
	if observer != nil && observer.Observe(stage) != nil {
		return ErrPersistence
	}
	return phase(ctx)
}
