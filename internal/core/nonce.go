package core

import "time"

// nonceCache remembers nonces for a bounded window so a captured lock
// command cannot be replayed. Old entries are pruned on every add.
type nonceCache struct {
	ttl  time.Duration
	seen map[string]time.Time
}

func newNonceCache(ttl time.Duration) *nonceCache {
	return &nonceCache{ttl: ttl, seen: make(map[string]time.Time)}
}

// add returns false when the nonce was already seen within the TTL.
func (n *nonceCache) add(nonce string, now time.Time) bool {
	for k, t := range n.seen {
		if now.Sub(t) > n.ttl {
			delete(n.seen, k)
		}
	}
	if _, dup := n.seen[nonce]; dup {
		return false
	}
	n.seen[nonce] = now
	return true
}
