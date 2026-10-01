package auth

import (
	"context"
	"github.com/adikezh/siem-triage-agent/internal/store"
)

func StoreAccess(s *store.Store, envHash, envRole string) Access {
	return Access{EnvHash: envHash, EnvRole: envRole, Initialized: s.HasAPIKeys,
		Lookup: func(ctx context.Context, hash string) (Identity, bool, error) {
			key, ok, err := s.LookupAPIKeyHash(ctx, hash)
			return Identity{Actor: key.Name, Role: key.Role}, ok, err
		},
	}
}
