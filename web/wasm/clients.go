//go:build js && wasm

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/bytemare/opaque"
)

// clientEntry wraps an OPAQUE client with a creation timestamp for TTL enforcement.
type clientEntry struct {
	client    *opaque.Client
	createdAt time.Time
}

// clientTTL is the maximum age of a pending OPAQUE client entry before it expires.
const clientTTL = 5 * time.Minute

// maxPendingClients caps the registry to prevent memory exhaustion.
const maxPendingClients = 10000

// clientRegistry stores OPAQUE client instances between Start and Finish calls.
// Keyed by a random hex ID returned to JS.
var (
	clientMu       sync.Mutex
	pendingClients = make(map[string]*clientEntry)
)

func storeClient(client *opaque.Client) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("generate client ID: %w", err)
	}
	key := hex.EncodeToString(id)
	clientMu.Lock()
	if len(pendingClients) >= maxPendingClients {
		clientMu.Unlock()
		return "", fmt.Errorf("too many pending OPAQUE sessions")
	}
	pendingClients[key] = &clientEntry{
		client:    client,
		createdAt: time.Now(),
	}
	clientMu.Unlock()
	return key, nil
}

func takeClient(key string) (*opaque.Client, error) {
	clientMu.Lock()
	entry, ok := pendingClients[key]
	if ok {
		delete(pendingClients, key)
	}
	clientMu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no pending OPAQUE state for client_id %s", key)
	}
	if time.Since(entry.createdAt) > clientTTL {
		return nil, fmt.Errorf("OPAQUE client state expired for client_id %s", key)
	}
	return entry.client, nil
}

// cleanupExpiredClients removes expired entries from pendingClients.
// Runs periodically in a background goroutine.
func cleanupExpiredClients() {
	for {
		time.Sleep(1 * time.Minute)
		clientMu.Lock()
		now := time.Now()
		for key, entry := range pendingClients {
			if now.Sub(entry.createdAt) > clientTTL {
				delete(pendingClients, key)
			}
		}
		clientMu.Unlock()
	}
}
