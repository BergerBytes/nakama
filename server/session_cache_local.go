package server

import (
	"context"
	"fmt"
	"github.com/gofrs/uuid"
	"sync"
	"time"
)

type sessionCacheUser struct {
	sessionTokens map[string]int64
	refreshTokens map[string]int64
}

type LocalSessionCache struct {
	sync.RWMutex

	ctx         context.Context
	ctxCancelFn context.CancelFunc

	cache map[uuid.UUID]*sessionCacheUser
}

func NewLocalSessionCache(tokenExpirySec int64) SessionCache {
	ctx, ctxCancelFn := context.WithCancel(context.Background())

	s := &LocalSessionCache{
		ctx:         ctx,
		ctxCancelFn: ctxCancelFn,

		cache: make(map[uuid.UUID]*sessionCacheUser),
	}

	go func() {
		ticker := time.NewTicker(2 * time.Duration(tokenExpirySec) * time.Second)
		for {
			select {
			case <-s.ctx.Done():
				ticker.Stop()
				return
			case t := <-ticker.C:
				tMs := t.UTC().Unix()
				s.Lock()
				for userID, cache := range s.cache {
					for token, exp := range cache.sessionTokens {
						if exp <= tMs {
							delete(cache.sessionTokens, token)
						}
					}
					for token, exp := range cache.refreshTokens {
						if exp <= tMs {
							delete(cache.refreshTokens, token)
						}
					}
					if len(cache.sessionTokens) == 0 && len(cache.refreshTokens) == 0 {
						delete(s.cache, userID)
					}
				}
				s.Unlock()
			}
		}
	}()

	return s
}

func (s *LocalSessionCache) Stop() {
	s.ctxCancelFn()
}

func (s *LocalSessionCache) IsValidSession(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	cache, found := s.cache[userID]
	if !found {
		s.RUnlock()
		return false
	}
	_, found = cache.sessionTokens[token]
	s.RUnlock()
	return found
}

func (s *LocalSessionCache) IsValidRefresh(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	cache, found := s.cache[userID]
	if !found {
		s.RUnlock()
		return false
	}
	_, found = cache.refreshTokens[token]
	s.RUnlock()
	return found
}

func (s *LocalSessionCache) Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	fmt.Println("add", userID, sessionExp, sessionToken, refreshExp, refreshToken)

	cache, found := s.cache[userID]
	if !found {
		cache = &sessionCacheUser{
			sessionTokens: make(map[string]int64),
			refreshTokens: make(map[string]int64),
		}
		s.cache[userID] = cache
	}
	if sessionToken != "" {
		cache.sessionTokens[sessionToken] = sessionExp + 1
	}
	if refreshToken != "" {
		cache.refreshTokens[refreshToken] = refreshExp + 1
	}
	s.Unlock()
}

func (s *LocalSessionCache) Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	cache, found := s.cache[userID]
	if !found {
		s.Unlock()
		return
	}
	if sessionToken != "" {
		delete(cache.sessionTokens, sessionToken)
	}
	if refreshToken != "" {
		delete(cache.refreshTokens, refreshToken)
	}
	if len(cache.sessionTokens) == 0 && len(cache.refreshTokens) == 0 {
		delete(s.cache, userID)
	}
	s.Unlock()
}

func (s *LocalSessionCache) RemoveAll(userID uuid.UUID) {
	s.Lock()
	delete(s.cache, userID)
	s.Unlock()
}

func (s *LocalSessionCache) Ban(userIDs []uuid.UUID) {
	s.Lock()
	for _, userID := range userIDs {
		delete(s.cache, userID)
	}
	s.Unlock()
}

func (s *LocalSessionCache) Unban(userIDs []uuid.UUID) {}
