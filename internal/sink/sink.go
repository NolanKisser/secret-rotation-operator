// Package sink pushes rotated secret material to systems outside the cluster.
package sink

import (
	"context"
)

// Sink receives every new version of a managed Secret.
//
// Implementations must be idempotent: the controller retries Push with the
// same (version, data) pair until it succeeds, and may call it again after a
// crash between a successful Push and the status update recording it.
type Sink interface {
	// Name identifies the sink in conditions, events, and metrics.
	Name() string
	// Push publishes data as the given version.
	Push(ctx context.Context, req PushRequest) error
}

// PushRequest is one Secret version destined for a sink.
type PushRequest struct {
	// OwnerUID is the UID of the SecretRotation, used to build idempotency keys
	// that stay stable across operator restarts.
	OwnerUID string
	Version  int64
	Data     map[string][]byte
}
