// Copyright 2021 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
)

type SessionCache interface {
	Stop()

	// Check if a given user, expiry, and session token combination is valid.
	IsValidSession(userID uuid.UUID, exp int64, token string) bool
	// Check if a given user, expiry, and refresh token combination is valid.
	IsValidRefresh(userID uuid.UUID, exp int64, token string) bool
	// Add a valid session and/or refresh token for a given user.
	Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string)
	// Remove a session and/or refresh token for a given user.
	Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string)
	// Remove all of a user's session and refresh tokens.
	RemoveAll(userID uuid.UUID)
	// Mark a set of users as banned.
	Ban(userIDs []uuid.UUID)
	// Unban a set of users.
	Unban(userIDs []uuid.UUID)
}

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

type RedisSessionCache struct {
	sync.RWMutex

	ctx         context.Context
	ctxCancelFn context.CancelFunc
	logger      *zap.Logger

	client *redis.Client
}

func NewRedisSessionCache(address string, logger *zap.Logger) SessionCache {
	if address == "" {
		return nil
	}

	logger.Info("Initializing Redis session cache", zap.String("address", address))

	options, err := redis.ParseURL(address)
	if err != nil {
		return nil
	}

	options.DB = 472840

	ctx, ctxCancelFn := context.WithCancel(context.Background())

	s := &RedisSessionCache{
		ctx:         ctx,
		ctxCancelFn: ctxCancelFn,
		logger:      logger,
		client:      redis.NewClient(options),
	}

	_, err = s.client.Ping(s.ctx).Result()
	if err != nil {
		ctxCancelFn()
		logger.Error("Could not initialize Redis session cache", zap.Error(err))
		return nil
	}

	logger.Info("Redis session cache initialized")

	return s
}

func (s *RedisSessionCache) Stop() {
	_ = s.client.Close()
	s.ctxCancelFn()
}

func (s *RedisSessionCache) IsValidSession(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	defer s.RUnlock()

	if isBanned := s.IsBanned(userID); isBanned {
		return false
	}

	key := fmt.Sprintf("%s:%s:%s", userID, tokenKindSession, s.GetSessionScope(token))
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

func (s *RedisSessionCache) IsValidRefresh(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	defer s.RUnlock()

	if isBanned := s.IsBanned(userID); isBanned {
		return false
	}

	key := fmt.Sprintf("%s:%s:%s", userID, tokenKindRefresh, s.GetSessionScope(token))
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

func (s *RedisSessionCache) Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	defer s.Unlock()

	if isBanned := s.IsBanned(userID); isBanned {
		return
	}

	if sessionToken != "" {
		s.AddToken(userID.String(), sessionToken, tokenKindSession, time.Duration(sessionExp)*time.Second)
	}

	if refreshToken != "" {
		s.AddToken(userID.String(), refreshToken, tokenKindRefresh, time.Duration(refreshExp)*time.Second)
	}
}

func (s *RedisSessionCache) Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	defer s.Unlock()

	if sessionToken != "" {
		s.RemoveToken(userID.String(), sessionToken, tokenKindSession)
	}

	if refreshToken != "" {
		s.RemoveToken(userID.String(), refreshToken, tokenKindRefresh)
	}
}

func (s *RedisSessionCache) RemoveAll(userID uuid.UUID) {
	s.Lock()
	defer s.Unlock()

	userSessionKeys, err := s.GetSessionKeys(userID.String())
	if err != nil {
		s.logger.Error("Error getting session keys", zap.Error(err))
		return
	}

	for _, key := range userSessionKeys {
		s.client.Del(s.ctx, key)
	}
}

func (s *RedisSessionCache) Ban(userIDs []uuid.UUID) {
	s.Lock()
	defer s.Unlock()
	for _, userID := range userIDs {
		s.client.Set(s.ctx, fmt.Sprintf("%s:%s", "BAN", userID), "true", 0)

		userSessionKeys, err := s.GetSessionKeys(userID.String())
		if err != nil {
			s.logger.Error("Error getting session keys", zap.Error(err))
			continue
		}

		for _, key := range userSessionKeys {
			s.client.Del(s.ctx, key)
		}
	}
}

func (s *RedisSessionCache) Unban(userIDs []uuid.UUID) {
	s.Lock()
	defer s.Unlock()
	for _, userID := range userIDs {
		s.client.Del(s.ctx, fmt.Sprintf("%s:%s", "BAN", userID))
	}
}

func (s *RedisSessionCache) parseClaims(in string) (map[string]interface{}, error) {
	token, _ := jwt.Parse(in, nil)

	if token == nil {
		s.logger.Error("Could not parse token")
		return map[string]interface{}{}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		s.logger.Error("Could not parse claims")
		return map[string]interface{}{}, nil
	}

	return claims, nil
}

// GetSessionScope returns the session scope in the given token.
func (s *RedisSessionCache) GetSessionScope(token string) string {
	claims, err := s.parseClaims(token)
	if err != nil {
		s.logger.Error("Error parsing session token claims", zap.Error(err))
		return "global"
	}

	sessionScope, ok := claims["session_scope"].(string)
	if !ok {
		s.logger.Error("Error parsing session token claims")
		return "global"
	}

	return sessionScope
}

type Key struct {
	UserID    string
	TokenKind string
	Scope     string
}

const (
	tokenKindSession = "token"
	tokenKindRefresh = "refresh"
)

// IsBanned returns true if the user is banned.
func (s *RedisSessionCache) IsBanned(userID uuid.UUID) bool {
	s.RLock()
	defer s.RUnlock()

	key := fmt.Sprintf("%s:%s", "BAN", userID)
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

// AddToken adds a token to the cache.
func (s *RedisSessionCache) AddToken(userId string, token string, tokenKind string, expiration time.Duration) {
	s.Lock()
	defer s.Unlock()

	sessionScope := s.GetSessionScope(token)

	key := fmt.Sprintf("%s:%s:%s", userId, tokenKind, sessionScope)
	s.client.Set(s.ctx, key, token, expiration)
}

// RemoveToken removes a token from the cache.
func (s *RedisSessionCache) RemoveToken(userId string, token string, tokenKind string) {
	s.Lock()
	defer s.Unlock()

	sessionScope := s.GetSessionScope(token)

	key := fmt.Sprintf("%s:%s:%s", userId, tokenKind, sessionScope)
	s.client.Del(s.ctx, key)
}

// GetSessionKeys returns all session keys for a given user.
func (s *RedisSessionCache) GetSessionKeys(userId string) ([]string, error) {
	s.RLock()
	defer s.RUnlock()

	var cursor uint64

	// pattern to match keys
	pattern := userId + ":*"

	// use redis.Scan to retrieve all keys that match the pattern
	var keys []string
	iter := s.client.Scan(s.ctx, cursor, pattern, 100).Iterator()
	for iter.Next(s.ctx) {
		keys = append(keys, iter.Val())
	}

	return keys, nil
}

func (s *RedisSessionCache) GetSessionTokens(userId string) (map[Key]string, error) {
	s.RLock()
	defer s.RUnlock()

	var cursor uint64

	// pattern to match keys
	pattern := userId + ":*"

	// use redis.Scan to retrieve all keys that match the pattern
	var keys map[Key]string
	iter := s.client.Scan(s.ctx, cursor, pattern, 100).Iterator()
	for iter.Next(s.ctx) {
		keyString := iter.Val()
		parts := strings.Split(keyString, ":")

		key := Key{
			UserID:    parts[0],
			TokenKind: parts[1],
			Scope:     parts[2],
		}

		keys[key] = s.client.Get(s.ctx, keyString).Val()
	}

	return keys, nil
}
