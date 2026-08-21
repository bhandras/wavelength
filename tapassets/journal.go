package tapassets

import (
	"context"
	"errors"
)

var (
	// ErrStoreNotFound reports that a journal key has no durable value.
	ErrStoreNotFound = errors.New("asset transition state not found")

	// ErrReconciliationRequired reports a commit whose outcome is unknown.
	ErrReconciliationRequired = errors.New("asset transition " +
		"reconciliation required")
)

// Store persists opaque transition state. Implementations must atomically
// replace a value and serialize operations for the same key.
type Store interface {
	Load(context.Context, string) ([]byte, error)

	Store(context.Context, string, []byte) error
}
